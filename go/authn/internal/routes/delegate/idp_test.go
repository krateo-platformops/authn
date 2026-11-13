package delegate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/routes/jwks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	mcpAudience = "https://cmp.example/mcp"
	kcKID       = "kc1"
	// idpMapping lets the agent exchange Keycloak access tokens for the MCP
	// endpoint, and ask for an "agentiko" audience.
	idpDelegation = `{"allowed":true,"subjectTokens":[{"oidcConfig":"keycloak","audiences":["` + mcpAudience + `"]}],"audiences":["agentiko"]}`
)

// realm is a fake Keycloak realm: its discovery document and its JWKS,
// signed by key.
type realm struct {
	issuer string
	key    *rsa.PrivateKey
}

func newRealm(t *testing.T) realm {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/krateo/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": issuer, "jwks_uri": issuer + "/certs",
				"authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token",
			})
		case "/realms/krateo/certs":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": kcKID, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	issuer = srv.URL + "/realms/krateo"
	return realm{issuer: issuer, key: key}
}

// accessToken is a Keycloak access token for alice, signed by key, with
// claims overriding the defaults (nil removes one).
func (k realm) accessToken(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, claims map[string]any) string {
	t.Helper()
	return k.sign(t, key, method, nil, claims)
}

// sign is accessToken with header overriding its header too.
func (k realm) sign(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, header, claims map[string]any) string {
	t.Helper()
	c := jwt.MapClaims{
		"iss": k.issuer, "sub": "uid-alice", "aud": mcpAudience, "typ": "Bearer", "preferred_username": "alice",
		"groups": []any{"tenants"}, "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
	}
	for name, v := range claims {
		if v == nil {
			delete(c, name)
			continue
		}
		c[name] = v
	}
	tok := jwt.NewWithClaims(method, c)
	tok.Header["kid"] = kcKID
	for name, v := range header {
		if v == nil {
			delete(tok.Header, name)
			continue
		}
		tok.Header[name] = v
	}
	var signed string
	var err error
	if method == jwt.SigningMethodHS256 {
		signed, err = tok.SignedString(key.N.Bytes())
	} else {
		signed, err = tok.SignedString(key)
	}
	require.NoError(t, err)
	return signed
}

// claimOf is alice's claim, as her portal sign-in at the realm wrote it.
func (k realm) claimOf(sub string) string {
	return storage.EncodeClaim(storage.StrategyOIDC, k.issuer, sub)
}

// idpAPIServer is apiserver also serving the OIDCConfig keycloak, which
// points at the realm and admits allowedGroups.
func idpAPIServer(t *testing.T, k realm, delegation string, allowedGroups []string) *rest.Config {
	t.Helper()
	allowed, err := json.Marshal(allowedGroups)
	require.NoError(t, err)
	return idpAPIServerWith(t, delegation, map[string]string{"keycloak": `{"discoveryURL":"` + k.issuer +
		`/.well-known/openid-configuration","clientID":"krateo-portal","redirectURI":"https://cmp.example/auth","allowedGroups":` +
		string(allowed) + `}`})
}

// idpAPIServerWith is apiserver serving the OIDCConfigs specs, by name; any
// other OIDCConfig is not found.
func idpAPIServerWith(t *testing.T, delegation string, specs map[string]string) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	const configs = "/apis/oidc.authn.krateo.io/v1alpha1/namespaces/krateo-system/oidcconfigs/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			_, _ = w.Write([]byte(reviewOK))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			_, _ = w.Write([]byte(mapping(delegation)))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, configs):
			name := strings.TrimPrefix(r.URL.Path, configs)
			spec, ok := specs[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
				return
			}
			_, _ = w.Write([]byte(`{"apiVersion":"oidc.authn.krateo.io/v1alpha1","kind":"OIDCConfig",
				"metadata":{"name":"` + name + `","namespace":"krateo-system"},"spec":` + spec + `}`))
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// secrets is a NameLookup over session Secrets by username.
type secrets map[string]*corev1.Secret

func (s secrets) SessionSecret(_ context.Context, username string) (*corev1.Secret, error) {
	return s[username], nil
}
func (s secrets) Secret(context.Context, string) (*corev1.Secret, error) { return nil, nil }
func (s secrets) Provisioned(context.Context, string) (bool, error)      { return false, nil }
func (s secrets) BoundAsUser(context.Context, string) (bool, error)      { return false, nil }
func claimed(claim string) *corev1.Secret {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-clientconfig"}}
	if claim != "" {
		sec.Annotations = map[string]string{storage.ClaimAnnotation: claim}
	}
	return sec
}

var _ kubeconfig.NameLookup = secrets{}

// idpRoute is the route, served as main serves it, with an audit Recorder
// and the lookup.
func (k keys) idpRoute(t *testing.T, rc *rest.Config, lookup kubeconfig.NameLookup) (http.Handler, *audittest.Recorder) {
	t.Helper()
	rec, records := auditlogtest.New(t)
	return auditlog.Middleware(Route(rc, Options{
		PrivateKey: k.current, KeyID: "current",
		PreviousKeys: []jwks.Key{{KID: "previous", Pub: &k.previous.PublicKey}},
		Audit:        rec, Lookup: lookup,
	}).Handler()), records
}

func idpForm(subject string, audience ...string) url.Values {
	f := url.Values{"grant_type": {GrantType}, "subject_token_type": {TokenTypeAccessToken}, "subject_token": {subject}}
	for _, a := range audience {
		f.Add("audience", a)
	}
	return f
}

// The bridge's exchange (authn#155): alice's Keycloak access token, which the
// agent's mapping may exchange, for an authn token naming alice as subject,
// the agent as actor and "agentiko" as audience, never outliving the access
// token. Its record names both, and the audience.
func TestExchangeOfAnIdentityProvidersToken(t *testing.T) {
	k, kc := newKeys(t), newRealm(t)
	rc := idpAPIServer(t, kc, idpDelegation, []string{"tenants", "platform-admins"})
	h, records := k.idpRoute(t, rc, secrets{"alice": claimed(kc.claimOf("uid-alice"))})

	kcToken := kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"exp": time.Now().Add(2 * time.Minute).Unix()})
	rec := exchange(h, "sa", idpForm(kcToken, "agentiko"))
	out, nfo := issued(t, k, rec)
	assert.Equal(t, TokenTypeJWT, out.IssuedTokenType)
	assert.Equal(t, "alice", nfo.Username)
	assert.Equal(t, []string{"tenants"}, nfo.Groups)
	require.NotNil(t, nfo.Act)
	assert.Equal(t, "kagent", nfo.Act.Sub)
	assert.LessOrEqual(t, out.ExpiresIn, int64(120), "never past the access token")

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(out.AccessToken, claims)
	require.NoError(t, err)
	aud, err := claims.GetAudience()
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"agentiko"}, aud)

	r := auditlogtest.Only(t, records)
	assert.Equal(t, audit.OutcomeSuccess, auditlogtest.String(r, "krateo.audit.outcome"))
	assert.Equal(t, "alice", auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
	assert.Equal(t, "agentiko", auditlogtest.String(r, audit.KeyTokenAudience))

	// Without an audience, the token has none, and neither has the record.
	h, records = k.idpRoute(t, rc, secrets{"alice": claimed(kc.claimOf("uid-alice"))})
	rec = exchange(h, "sa", idpForm(kc.accessToken(t, kc.key, jwt.SigningMethodRS256, nil)))
	out, _ = issued(t, k, rec)
	claims = jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(out.AccessToken, claims)
	require.NoError(t, err)
	assert.NotContains(t, claims, "aud")
	assert.Empty(t, auditlogtest.String(auditlogtest.Only(t, records), audit.KeyTokenAudience))
}

// Every refusal of the exchange (authn#155): the answer the bridge maps, and
// a conformant denied record with its reason. A subject the provider
// verified is named on the record; one that didn't verify isn't.
func TestExchangeRefusals(t *testing.T) {
	k, kc := newKeys(t), newRealm(t)
	stranger := k.stranger
	signedIn := secrets{"alice": claimed(kc.claimOf("uid-alice"))}
	for _, tc := range []struct {
		name     string
		lookup   kubeconfig.NameLookup
		token    func(t *testing.T) string
		audience []string
		allowed  []string
		code     int
		cause    string
		reason   string
		named    bool   // the record names alice
		recAud   string // the record's token.audience
	}{
		{name: "never signed in", lookup: secrets{},
			code: http.StatusForbidden, cause: "SubjectNotSignedIn", reason: audit.DenialReasonSubjectNotSignedIn, named: true},
		{name: "the name is another identity's", lookup: secrets{"alice": claimed(kc.claimOf("uid-mallory"))},
			code: http.StatusForbidden, cause: "UsernameUnavailable", reason: audit.DenialReasonNameClaimed, named: true},
		{name: "the name's Secret is from before claims", lookup: secrets{"alice": claimed("")},
			code: http.StatusForbidden, cause: "UsernameUnavailable", reason: audit.DenialReasonNameHeldLegacy, named: true},
		{name: "in none of the OIDCConfig's allowedGroups", allowed: []string{"platform-admins"},
			code: http.StatusForbidden, cause: "GroupNotAllowed", reason: audit.DenialReasonGroupNotAllowed, named: true},
		{name: "a krateo: group from the provider",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"groups": []any{"tenants", "krateo:admins"}})
			},
			code: http.StatusForbidden, cause: "PlatformGroupNotAllowed", reason: audit.DenialReasonPlatformGroup, named: true},
		{name: "signed by another key",
			token: func(t *testing.T) string { return kc.accessToken(t, stranger, jwt.SigningMethodRS256, nil) },
			code:  http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "an HMAC signature with the public key (alg confusion)",
			token: func(t *testing.T) string { return kc.accessToken(t, kc.key, jwt.SigningMethodHS256, nil) },
			code:  http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "for another resource",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"aud": "https://other.example"})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "expired",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"exp": time.Now().Add(-5 * time.Minute).Unix()})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenExpired},
		{name: "an ID token the provider signed",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"typ": "ID"})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "a refresh token the provider signed",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"typ": "Refresh"})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "no typ at all",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"typ": nil})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "a kid the provider doesn't publish, on a token issued before its keys were read",
			token: func(t *testing.T) string {
				return kc.sign(t, stranger, jwt.SigningMethodRS256, map[string]any{"kid": "forged"},
					map[string]any{"iat": time.Now().Add(-time.Minute).Unix()})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "no issue time",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"iat": nil})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "issued in the future",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"iat": time.Now().Add(10 * time.Minute).Unix()})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "no sub",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"sub": nil})
			},
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", reason: audit.DenialReasonSubjectTokenInvalid},
		{name: "issued by a provider the mapping doesn't list",
			token: func(t *testing.T) string {
				return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, map[string]any{"iss": "https://elsewhere.example/realms/x"})
			},
			code: http.StatusForbidden, cause: "DelegationNotAllowed", reason: audit.DenialReasonDelegationNotAllowed},
		{name: "an audience the mapping doesn't allow", audience: []string{"snowplow"},
			code: http.StatusBadRequest, cause: "InvalidTarget", reason: audit.DenialReasonAudienceNotAllowed, recAud: "snowplow"},
		{name: "a malformed audience", audience: []string{"Not An Audience"},
			code: http.StatusBadRequest, cause: "InvalidRequestBody", reason: audit.DenialReasonInvalidRequest},
		{name: "two audiences", audience: []string{"agentiko", "agentiko"},
			code: http.StatusBadRequest, cause: "InvalidRequestBody", reason: audit.DenialReasonInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowed := tc.allowed
			if allowed == nil {
				allowed = []string{"tenants"}
			}
			lookup := tc.lookup
			if lookup == nil {
				lookup = signedIn
			}
			tokenFor := tc.token
			if tokenFor == nil {
				tokenFor = func(t *testing.T) string { return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, nil) }
			}
			h, records := k.idpRoute(t, idpAPIServer(t, kc, idpDelegation, allowed), lookup)
			rec := exchange(h, "sa", idpForm(tokenFor(t), tc.audience...))
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Equal(t, tc.cause, cause(t, rec))
			assert.NotContains(t, rec.Body.String(), "access_token")
			assert.NotContains(t, rec.Body.String(), kc.issuer, "the answer never names the provider's addresses")
			assert.NotContains(t, rec.Body.String(), "forged", "nor a kid")

			r := auditlogtest.Only(t, records)
			assert.Equal(t, audit.OutcomeDenied, auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, tc.reason, auditlogtest.String(r, "krateo.audit.denial_reason"))
			if tc.named {
				assert.Equal(t, "alice", auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
			} else {
				assert.Empty(t, auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
			}
			assert.Equal(t, tc.recAud, auditlogtest.String(r, audit.KeyTokenAudience))
		})
	}
}

// The audience applies to an authn subject token too: the delegated token
// of a person's authn token carries the requested audience.
func TestExchangeOfAnAuthnTokenCarriesTheAudience(t *testing.T) {
	k, kc := newKeys(t), newRealm(t)
	h, records := k.idpRoute(t, idpAPIServer(t, kc, idpDelegation, nil), secrets{})
	f := form(token(t, k.current, "current", time.Hour, nil))
	f.Set("audience", "agentiko")
	out, nfo := issued(t, k, exchange(h, "sa", f))
	assert.Equal(t, "alice", nfo.Username)
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(out.AccessToken, claims)
	require.NoError(t, err)
	aud, err := claims.GetAudience()
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"agentiko"}, aud)
	assert.Equal(t, "agentiko", auditlogtest.String(auditlogtest.Only(t, records), audit.KeyTokenAudience))
}

// An RFC 9068 access token, marked typ at+jwt in its header and carrying no
// typ claim, is an access token too.
func TestExchangeOfAnRFC9068AccessToken(t *testing.T) {
	k, kc := newKeys(t), newRealm(t)
	h, _ := k.idpRoute(t, idpAPIServer(t, kc, idpDelegation, nil), secrets{"alice": claimed(kc.claimOf("uid-alice"))})
	tok := kc.sign(t, kc.key, jwt.SigningMethodRS256, map[string]any{"typ": "at+jwt"}, map[string]any{"typ": nil})
	_, nfo := issued(t, k, exchange(h, "sa", idpForm(tok)))
	assert.Equal(t, "alice", nfo.Username)
}

// A source that can't be resolved doesn't fail exchanges another source
// verifies: it is skipped.
func TestExchangeSkipsAnUnresolvableSource(t *testing.T) {
	k, kc := newKeys(t), newRealm(t)
	delegation := `{"allowed":true,"subjectTokens":[{"oidcConfig":"gone","audiences":["` + mcpAudience + `"]},` +
		`{"oidcConfig":"keycloak","audiences":["` + mcpAudience + `"]}]}`
	rc := idpAPIServerWith(t, delegation, map[string]string{"keycloak": `{"discoveryURL":"` + kc.issuer + `/.well-known/openid-configuration"}`})
	h, _ := k.idpRoute(t, rc, secrets{"alice": claimed(kc.claimOf("uid-alice"))})
	_, nfo := issued(t, k, exchange(h, "sa", idpForm(kc.accessToken(t, kc.key, jwt.SigningMethodRS256, nil))))
	assert.Equal(t, "alice", nfo.Username)
}

// authn's failures to verify an identity provider's token (500
// IssuanceFailed, a failure record that names no subject): its sources can't
// be resolved, its OIDCConfig maps identities through a RESTAction, or its
// keys can't be read. The answer names neither the provider's addresses nor
// the OIDCConfig; the log does.
func TestExchangeFailures(t *testing.T) {
	k, kc := newKeys(t), newRealm(t)
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	discovery := `"discoveryURL":"` + kc.issuer + `/.well-known/openid-configuration"`
	for _, tc := range []struct {
		name   string
		specs  map[string]string
		token  func(t *testing.T) string
		answer string
	}{
		{name: "the only source's OIDCConfig is missing", specs: map[string]string{},
			answer: "couldn't be resolved"},
		{name: "the only source's provider is down", specs: map[string]string{"keycloak": `{"discoveryURL":"` + gone.URL + `/.well-known/openid-configuration"}`},
			answer: "couldn't be resolved"},
		{name: "the OIDCConfig maps identities through a RESTAction",
			specs:  map[string]string{"keycloak": `{` + discovery + `,"restActionRef":{"name":"userinfo","namespace":"krateo-system"}}`},
			answer: "RESTAction"},
		{name: "a kid the provider's keys, read just now, may predate",
			specs: map[string]string{"keycloak": `{` + discovery + `}`},
			token: func(t *testing.T) string {
				return kc.sign(t, k.stranger, jwt.SigningMethodRS256, map[string]any{"kid": "kc2"}, nil)
			},
			answer: "signing keys couldn't be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenFor := tc.token
			if tokenFor == nil {
				tokenFor = func(t *testing.T) string { return kc.accessToken(t, kc.key, jwt.SigningMethodRS256, nil) }
			}
			h, records := k.idpRoute(t, idpAPIServerWith(t, idpDelegation, tc.specs), secrets{"alice": claimed(kc.claimOf("uid-alice"))})
			rec := exchange(h, "sa", idpForm(tokenFor(t)))
			require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
			assert.Equal(t, "IssuanceFailed", cause(t, rec))
			assert.Contains(t, rec.Body.String(), tc.answer)
			for _, private := range []string{kc.issuer, gone.URL, "keycloak", "userinfo", "kc2"} {
				assert.NotContains(t, rec.Body.String(), private)
			}

			r := auditlogtest.Only(t, records)
			assert.Equal(t, audit.OutcomeFailure, auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Empty(t, auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
		})
	}
}
