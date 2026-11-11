package delegate

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/routes/jwks"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

const reviewOK = `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
	"status":{"authenticated":true,"audiences":["authn"],
	"user":{"username":"system:serviceaccount:krateo-system:agent"}}}`

// mapping is the agent's ServiceAccount mapping, with delegation as given
// (empty: none).
func mapping(delegation string) string { return mappingAs(delegation, "") }

// mappingAs is mapping with spec.principal set (empty: unset).
func mappingAs(delegation, principal string) string {
	spec := `"serviceAccountRef":{"namespace":"krateo-system","name":"agent"},"groups":["krateo:agents"]`
	if delegation != "" {
		spec += `,"delegation":` + delegation
	}
	if principal != "" {
		spec += `,"principal":"` + principal + `"`
	}
	return `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[` +
		`{"metadata":{"name":"kagent","namespace":"krateo-system"},"spec":{` + spec + `}}]}`
}

// apiserver answers the TokenReview and the mapping list, and counts calls.
func apiserver(t *testing.T, mappings string) (*rest.Config, *atomic.Int32) {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			_, _ = w.Write([]byte(reviewOK))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			_, _ = w.Write([]byte(mappings))
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}, &calls
}

type keys struct{ current, previous, stranger *rsa.PrivateKey }

func newKeys(t *testing.T) keys {
	t.Helper()
	gen := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		return k
	}
	return keys{gen(), gen(), gen()}
}

func (k keys) route(rc *rest.Config) http.Handler {
	return Route(rc, Options{
		PrivateKey:   k.current,
		KeyID:        "current",
		PreviousKeys: []jwks.Key{{KID: "previous", Pub: &k.previous.PublicKey}},
	}).Handler()
}

// recorded is route with an audit Recorder, served as main serves it.
func (k keys) recorded(t *testing.T, rc *rest.Config) (http.Handler, *audittest.Recorder) {
	audit, records := auditlogtest.New(t)
	return auditlog.Middleware(Route(rc, Options{
		PrivateKey:   k.current,
		KeyID:        "current",
		PreviousKeys: []jwks.Key{{KID: "previous", Pub: &k.previous.PublicKey}},
		Audit:        audit,
	}).Handler()), records
}

// token is alice's authn token, as a person's sign-in issues it.
func token(t *testing.T, key *rsa.PrivateKey, kid string, ttl time.Duration, act *jwtutil.Actor) string {
	return tokenAs(t, key, kid, ttl, act, jwtutil.PrincipalHuman)
}

// tokenAs is token with the given principal claim (empty: none, as authn
// before 0.39 issued it).
func tokenAs(t *testing.T, key *rsa.PrivateKey, kid string, ttl time.Duration, act *jwtutil.Actor, p jwtutil.Principal) string {
	t.Helper()
	tok, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
		Username: "alice", Groups: []string{"devs", "krateo:loa:2"}, Duration: ttl,
		KeyID: kid, PrivateKey: key, Act: act, Principal: p,
	})
	require.NoError(t, err)
	return tok
}

func exchange(h http.Handler, bearer string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func form(subject string) url.Values {
	return url.Values{"grant_type": {GrantType}, "subject_token_type": {TokenTypeJWT}, "subject_token": {subject}}
}

func cause(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var st struct {
		Details struct {
			Causes []struct {
				Reason string `json:"reason"`
			} `json:"causes"`
		} `json:"details"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &st), rec.Body.String())
	require.NotEmpty(t, st.Details.Causes, rec.Body.String())
	return st.Details.Causes[0].Reason
}

type exchanged struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

func issued(t *testing.T, k keys, rec *httptest.ResponseRecorder) (exchanged, jwtutil.UserInfo) {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out exchanged
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	nfo, err := jwtutil.Validate(&k.current.PublicKey, out.AccessToken)
	require.NoError(t, err)
	return out, nfo
}

// A service that opted in gets a token naming the person as subject and
// itself as actor, without the person's step-up group, as RFC 8693 answers it.
func TestDelegationIssuesActorToken(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	h, records := k.recorded(t, rc)
	rec := exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil)))

	// One conformant record: the actor, acting for alice, through its mapping (AUDIT-4).
	r := auditlogtest.Only(t, records)
	assert.Equal(t, "authn.delegate", auditlogtest.String(r, "krateo.action"))
	assert.Equal(t, "success", auditlogtest.String(r, "krateo.audit.outcome"))
	assert.Equal(t, "kagent", auditlogtest.String(r, "user.name"))
	assert.Equal(t, "alice", auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
	assert.Equal(t, "serviceaccounts", auditlogtest.String(r, "krateo.audit.object_ref.resource"))

	out, nfo := issued(t, k, rec)
	assert.Equal(t, TokenTypeJWT, out.IssuedTokenType)
	assert.Equal(t, "Bearer", out.TokenType)
	assert.InDelta(t, DefaultTTL.Seconds(), out.ExpiresIn, 2)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	assert.Equal(t, "alice", nfo.Username)
	assert.Equal(t, []string{"devs"}, nfo.Groups, "a step-up group never passes through delegation")
	assert.Equal(t, &jwtutil.Actor{Sub: "kagent", Principal: jwtutil.PrincipalService}, nfo.Act,
		"a mapping that declares no principal acts as a service")
	assert.Equal(t, []string{"kagent", "alice"}, nfo.DelegationChain())
	assert.Equal(t, jwtutil.PrincipalHuman, nfo.Principal, "the subject keeps its own kind")
}

// The actor's link carries the kind its mapping declares; the subject's
// kind is copied from its verified token, and a subject token without one
// (from authn before 0.39) yields a delegated token without one.
func TestDelegationCarriesPrincipals(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mappingAs(`{"allowed":true}`, "agent"))

	_, nfo := issued(t, k, exchange(k.route(rc), "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil))))
	assert.Equal(t, jwtutil.PrincipalHuman, nfo.Principal)
	assert.Equal(t, &jwtutil.Actor{Sub: "kagent", Principal: jwtutil.PrincipalAgent}, nfo.Act)
	assert.Equal(t, jwtutil.PrincipalAgent, nfo.ActorPrincipal())

	_, nfo = issued(t, k, exchange(k.route(rc), "projected-sa-token", form(tokenAs(t, k.current, "current", time.Hour, nil, ""))))
	assert.Equal(t, jwtutil.Principal(""), nfo.Principal, "never guessed")
	assert.Equal(t, jwtutil.PrincipalAgent, nfo.ActorPrincipal())
}

// A delegated token never outlives the person's own token.
func TestDelegationNeverOutlivesTheSubject(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	rec := exchange(k.route(rc), "projected-sa-token", form(token(t, k.current, "current", 5*time.Minute, nil)))

	out, _ := issued(t, k, rec)
	assert.LessOrEqual(t, out.ExpiresIn, int64(300))
	assert.Greater(t, out.ExpiresIn, int64(290))
}

// Exchanging a delegated token again nests the chain, current actor first.
func TestDelegationNestsAChain(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	subject := token(t, k.current, "current", time.Hour, &jwtutil.Actor{Sub: "portal-agent", Principal: jwtutil.PrincipalAgent})
	_, nfo := issued(t, k, exchange(k.route(rc), "projected-sa-token", form(subject)))

	assert.Equal(t, &jwtutil.Actor{Sub: "kagent", Principal: jwtutil.PrincipalService,
		Act: &jwtutil.Actor{Sub: "portal-agent", Principal: jwtutil.PrincipalAgent}}, nfo.Act,
		"the earlier links keep their kinds")
	assert.Equal(t, []string{"kagent", "portal-agent", "alice"}, nfo.DelegationChain())
}

// A token signed before a key rotation is still accepted as the subject.
func TestDelegationAcceptsAPreviousKey(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	_, nfo := issued(t, k, exchange(k.route(rc), "projected-sa-token", form(token(t, k.previous, "previous", time.Hour, nil))))
	assert.Equal(t, "alice", nfo.Username)
}

// Refusals: each carries its cause, and none issues a token.
// A signing failure after every check passed is a failure record of the
// issuance, with no status code: authn itself failed.
func TestDelegationSigningFailureIsRecorded(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	audit, records := auditlogtest.New(t)
	// A key far too small to sign a JWT: every signature with it fails. The
	// subject token verifies through the previous key, so only the signing fails.
	tiny := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17},
		D:         big.NewInt(2753),
		Primes:    []*big.Int{big.NewInt(61), big.NewInt(53)},
	}
	h := auditlog.Middleware(Route(rc, Options{
		PrivateKey:   tiny,
		KeyID:        "current",
		PreviousKeys: []jwks.Key{{KID: "previous", Pub: &k.previous.PublicKey}},
		Audit:        audit,
	}).Handler())
	rec := exchange(h, "projected-sa-token", form(token(t, k.previous, "previous", time.Hour, nil)))
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	r := auditlogtest.Only(t, records)
	assert.Equal(t, "failure", auditlogtest.String(r, "krateo.audit.outcome"))
	assert.Equal(t, "alice", auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
	for _, kv := range audittest.Attributes(r) {
		assert.NotEqual(t, "http.response.status_code", string(kv.Key), "no authority answered")
	}
}

// An authenticated actor whose mapping doesn't allow delegation is a denied
// record of that mapping; a caller with no bearer at all is not recorded.
func TestDelegationRefusalsAreRecorded(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":false}`))
	h, records := k.recorded(t, rc)
	rec := exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil)))
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	r := auditlogtest.Only(t, records)
	assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
	assert.Equal(t, "kagent", auditlogtest.String(r, "krateo.audit.object_ref.name"))

	h, records = k.recorded(t, rc)
	rec = exchange(h, "", form(token(t, k.current, "current", time.Hour, nil)))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, records.Records(), "no actor was verified, so there is no record")
}

func TestDelegationRefusals(t *testing.T) {
	k := newKeys(t)
	valid := func(t *testing.T) string { return token(t, k.current, "current", time.Hour, nil) }
	for _, tc := range []struct {
		name     string
		mappings string
		bearer   string
		form     func(t *testing.T) url.Values
		code     int
		cause    string
		apiCalls bool
	}{
		{name: "no bearer", mappings: mapping(`{"allowed":true}`), form: func(t *testing.T) url.Values { return form(valid(t)) },
			code: http.StatusUnauthorized, cause: "MissingBearer"},
		{name: "wrong grant type", mappings: mapping(`{"allowed":true}`), bearer: "sa",
			form: func(t *testing.T) url.Values {
				f := form(valid(t))
				f.Set("grant_type", "client_credentials")
				return f
			},
			code: http.StatusBadRequest, cause: "UnsupportedGrantType"},
		{name: "wrong subject token type", mappings: mapping(`{"allowed":true}`), bearer: "sa",
			form: func(t *testing.T) url.Values {
				f := form(valid(t))
				f.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
				return f
			},
			code: http.StatusBadRequest, cause: "UnsupportedSubjectToken"},
		{name: "no subject token", mappings: mapping(`{"allowed":true}`), bearer: "sa",
			form: func(*testing.T) url.Values { return form("") },
			code: http.StatusBadRequest, cause: "MissingSubjectToken"},
		{name: "service not opted in", mappings: mapping(""), bearer: "sa",
			form: func(t *testing.T) url.Values { return form(valid(t)) },
			code: http.StatusForbidden, cause: "DelegationNotAllowed", apiCalls: true},
		{name: "opt-in set to false", mappings: mapping(`{"allowed":false}`), bearer: "sa",
			form: func(t *testing.T) url.Values { return form(valid(t)) },
			code: http.StatusForbidden, cause: "DelegationNotAllowed", apiCalls: true},
		{name: "subject signed by another key", mappings: mapping(`{"allowed":true}`), bearer: "sa",
			form: func(t *testing.T) url.Values { return form(token(t, k.stranger, "current", time.Hour, nil)) },
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", apiCalls: true},
		{name: "subject expired", mappings: mapping(`{"allowed":true}`), bearer: "sa",
			form: func(t *testing.T) url.Values { return form(token(t, k.current, "current", -time.Minute, nil)) },
			code: http.StatusUnauthorized, cause: "SubjectTokenInvalid", apiCalls: true},
		{name: "chain deeper than the mapping allows", mappings: mapping(`{"allowed":true,"maxDepth":1}`), bearer: "sa",
			form: func(t *testing.T) url.Values {
				return form(token(t, k.current, "current", time.Hour, &jwtutil.Actor{Sub: "portal-agent"}))
			},
			code: http.StatusForbidden, cause: "DelegationTooDeep", apiCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, calls := apiserver(t, tc.mappings)
			h, records := k.recorded(t, rc)
			rec := exchange(h, tc.bearer, tc.form(t))
			assert.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Equal(t, tc.cause, cause(t, rec))
			assert.NotContains(t, rec.Body.String(), `"access_token":`, "no token is issued")
			if !tc.apiCalls {
				assert.Zero(t, calls.Load(), "a malformed request is refused before the apiserver is asked")
				assert.Empty(t, records.Records(), "no actor was verified, so there is no record")
				return
			}
			// The actor is verified: every refusal of it is one denied record of
			// the issuance (AUDIT-4), whichever check refused it.
			r := auditlogtest.Only(t, records)
			assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, "create", auditlogtest.String(r, "krateo.audit.verb"))
			assert.Equal(t, "token", auditlogtest.String(r, "krateo.audit.object_ref.subresource"))
			assert.Equal(t, "kagent", auditlogtest.String(r, "krateo.audit.object_ref.name"))
			// The schema's reason for each refusal; the subject token's has none.
			wantReason := map[string]string{
				"DelegationNotAllowed": "delegation_not_allowed",
				"DelegationTooDeep":    "delegation_too_deep",
				"SubjectTokenInvalid":  "",
			}
			want, known := wantReason[tc.cause]
			require.True(t, known, "every recorded refusal has an expected reason: %s", tc.cause)
			assert.Equal(t, want, auditlogtest.String(r, "krateo.audit.denial_reason"))
		})
	}
}
