package delegate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// clientAPI is an apiserver holding one mapping, read by name, and Secrets.
type clientAPI struct {
	mu      sync.Mutex
	mapping string
	secrets map[string][]byte // the Secret's tls.crt
	code    int               // when set, what every read of the mapping answers
}

func (a *clientAPI) set(f func(*clientAPI)) { a.mu.Lock(); defer a.mu.Unlock(); f(a) }

func newClientAPI(t *testing.T) (*clientAPI, *rest.Config) {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	a := &clientAPI{secrets: map[string][]byte{}}
	notFound := `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"%s not found","reason":"NotFound","code":404}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		name, isSecret := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/krateo-system/secrets/")
		crt, held := a.secrets[name]
		switch {
		case r.Method == http.MethodGet && isSecret && held:
			_, _ = fmt.Fprintf(w, `{"kind":"Secret","apiVersion":"v1","metadata":{"name":%q},"data":{"tls.crt":%q}}`, name, base64.StdEncoding.EncodeToString(crt))
		case r.Method == http.MethodGet && !isSecret && a.code != 0:
			w.WriteHeader(a.code)
			_, _ = fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"boom","code":%d}`, a.code)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts/gateway" && a.mapping != "":
			_, _ = w.Write([]byte(a.mapping))
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, notFound, name)
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return a, &rest.Config{Host: srv.URL}
}

// gatewayMapping is the gateway's mapping, with delegation and the Secret its
// key is in as given ("" for none).
func gatewayMapping(delegation, secret string) string {
	spec := `"serviceAccountRef":{"namespace":"krateo-system","name":"gw"}`
	if delegation != "" {
		spec += `,"delegation":` + delegation
	}
	if secret != "" {
		spec += `,"clientAssertion":{"certificateSecretName":"` + secret + `"}`
	}
	return `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccount",` +
		`"metadata":{"name":"gateway","namespace":"krateo-system"},"spec":{` + spec + `}}`
}

const toolsAudience = `{"allowed":true,"audiences":["tools.krateo-system"]}`

func certFor(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway"}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func validCert(t *testing.T, key crypto.Signer) []byte {
	return certFor(t, key, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// gateway is a service that signs client assertions, and the route it calls.
type gateway struct {
	keys    keys
	key     *rsa.PrivateKey
	api     *clientAPI
	handler http.Handler
	records *audittest.Recorder
	jti     int
}

func newGateway(t *testing.T, delegation string) *gateway {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	api, rc := newClientAPI(t)
	api.mapping, api.secrets["gateway-client"] = gatewayMapping(delegation, "gateway-client"), validCert(t, key)
	g := &gateway{keys: newKeys(t), key: key, api: api}
	rec, records := auditlogtest.New(t)
	r := Route(rc, Options{PrivateKey: g.keys.current, KeyID: "current", Lookup: everyoneSignedIn{},
		Generator: &fakeGenerator{}, Audit: rec, ClientAssertions: true})
	require.Equal(t, AssertionPath, r.Pattern())
	g.handler, g.records = auditlog.Middleware(r.Handler()), records
	return g
}

// claims are what agentgateway signs, with each entry of over set, or removed
// when nil.
func (g *gateway) claims(over map[string]any) jwt.MapClaims {
	g.jti++
	now := time.Now()
	c := jwt.MapClaims{"iss": "gateway", "sub": "gateway", "aud": "authn", "jti": fmt.Sprint("jti-", g.jti),
		"nbf": now.Add(-10 * time.Second).Unix(), "iat": now.Add(-10 * time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func (g *gateway) assertion(t *testing.T, over map[string]any) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, g.claims(over)).SignedString(g.key)
	require.NoError(t, err)
	return s
}

// form is the request agentgateway sends for subject, with assertion.
func (g *gateway) form(subject, assertion string) url.Values {
	f := form(subject)
	f.Set("audience", "tools.krateo-system")
	f.Set("client_id", "gateway")
	f.Set("client_assertion_type", ClientAssertionType)
	f.Set("client_assertion", assertion)
	return f
}

func (g *gateway) subject(t *testing.T) string {
	return token(t, g.keys.current, "current", time.Hour, nil)
}

func (g *gateway) exchange(t *testing.T, assertion string) *httptest.ResponseRecorder {
	return exchange(g.handler, "", g.form(g.subject(t), assertion))
}

// A service that registered a key exchanges a person's token with an assertion
// it signed, as agentgateway's built-in exchange sends it: the token is for the
// audience, the service is its actor, and the exchange is recorded as one
// authenticated by a ServiceAccount token is.
func TestClientAssertionExchanges(t *testing.T) {
	g := newGateway(t, toolsAudience)
	_, nfo := issued(t, g.keys, g.exchange(t, g.assertion(t, nil)))
	assert.Equal(t, "alice", nfo.Username)
	assert.Equal(t, &jwtutil.Actor{Sub: "gateway", Principal: jwtutil.PrincipalService}, nfo.Act)
	r := auditlogtest.OnlyAction(t, g.records, auditlog.ActionDelegate)
	assert.Equal(t, "success", auditlogtest.String(r, "krateo.audit.outcome"))
	assert.Equal(t, "gateway", auditlogtest.String(r, "user.name"))
	assert.Equal(t, "alice", auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
}

// Every algorithm is the key's own, and client_id may be left out (RFC 7521
// §4.2).
func TestClientAssertionAlgorithms(t *testing.T) {
	g := newGateway(t, toolsAudience)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		method jwt.SigningMethod
		key    crypto.Signer
	}{{jwt.SigningMethodRS256, g.key}, {jwt.SigningMethodRS512, g.key}, {jwt.SigningMethodPS256, g.key}, {jwt.SigningMethodES256, ec}} {
		g.api.set(func(a *clientAPI) { a.secrets["gateway-client"] = validCert(t, tc.key) })
		s, err := jwt.NewWithClaims(tc.method, g.claims(nil)).SignedString(tc.key)
		require.NoError(t, err)
		f := g.form(g.subject(t), s)
		f.Del("client_id")
		assert.Equal(t, http.StatusOK, exchange(g.handler, "", f).Code, tc.method.Alg())
	}
}

// An algorithm outside the list is refused even when the registered key is of
// its kind and the signature verifies.
func TestClientAssertionOfAnUnlistedAlgorithm(t *testing.T) {
	g := newGateway(t, toolsAudience)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	g.api.set(func(a *clientAPI) { a.secrets["gateway-client"] = validCert(t, key) })
	s, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, g.claims(nil)).SignedString(key)
	require.NoError(t, err)
	_, err = jwt.Parse(s, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithLeeway(time.Minute))
	require.NoError(t, err, "control: it verifies")
	rec := exchange(g.handler, "", g.form(g.subject(t), s))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, string(CauseClientAssertionInvalid), cause(t, rec))
}

// A client whose clock is a few seconds off is understood.
func TestClientAssertionSkew(t *testing.T) {
	g := newGateway(t, toolsAudience)
	now := time.Now()
	for name, over := range map[string]map[string]any{
		"ahead":  {"iat": now.Add(5 * time.Second).Unix(), "nbf": now.Add(5 * time.Second).Unix()},
		"behind": {"exp": now.Add(-5 * time.Second).Unix()},
	} {
		assert.Equal(t, http.StatusOK, g.exchange(t, g.assertion(t, over)).Code, name)
	}
}

// Everything that isn't the service's own fresh assertion to authn is one
// answer, 401 ClientAssertionInvalid, and leaves no record: nobody was
// authenticated. The control in each row is the same request unaltered.
func TestClientAssertionRefused(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sign := func(t *testing.T, m jwt.SigningMethod, key any, c jwt.MapClaims) string {
		t.Helper()
		s, err := jwt.NewWithClaims(m, c).SignedString(key)
		require.NoError(t, err)
		return s
	}
	now := time.Now()
	for name, build := range map[string]func(t *testing.T, g *gateway) url.Values{
		"another key": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), sign(t, jwt.SigningMethodRS256, other, g.claims(nil)))
		},
		"unsigned": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, g.claims(nil)))
		},
		"the public key as a shared secret": func(t *testing.T, g *gateway) url.Values {
			pub, err := x509.MarshalPKIXPublicKey(&g.key.PublicKey)
			require.NoError(t, err)
			return g.form(g.subject(t), sign(t, jwt.SigningMethodHS256, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), g.claims(nil)))
		},
		"not a JWT":         func(t *testing.T, g *gateway) url.Values { return g.form(g.subject(t), "x") },
		"authn's own token": func(t *testing.T, g *gateway) url.Values { return g.form(g.subject(t), g.subject(t)) },
		"for another audience": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"aud": "elsewhere"}))
		},
		"for no audience": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"aud": nil}))
		},
		"expired": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"exp": now.Add(-time.Minute).Unix()}))
		},
		"without expiry": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"exp": nil}))
		},
		"too long": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"exp": now.Add(11 * time.Minute).Unix()}))
		},
		"not yet valid": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"nbf": now.Add(time.Minute).Unix()}))
		},
		"issued in the future": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"iat": now.Add(time.Minute).Unix()}))
		},
		"without jti": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"jti": nil}))
		},
		"a huge jti": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"jti": strings.Repeat("a", 257)}))
		},
		"sub isn't iss": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"sub": "someone"}))
		},
		"without sub": func(t *testing.T, g *gateway) url.Values {
			return g.form(g.subject(t), g.assertion(t, map[string]any{"sub": nil}))
		},
		"an unknown service": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, map[string]any{"iss": "nobody", "sub": "nobody"}))
			f.Del("client_id")
			return f
		},
		"a path for a name": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, map[string]any{"iss": "../secrets/x", "sub": "../secrets/x"}))
			f.Del("client_id")
			return f
		},
		"without iss": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, map[string]any{"iss": nil}))
			f.Del("client_id")
			return f
		},
		"client_id isn't iss": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, nil))
			f.Set("client_id", "another")
			return f
		},
		"two client_ids": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, nil))
			f.Add("client_id", "gateway")
			return f
		},
		"no assertion": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), "")
			f.Del("client_assertion")
			return f
		},
		"an empty assertion": func(t *testing.T, g *gateway) url.Values { return g.form(g.subject(t), "") },
		"two assertions": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, nil))
			f.Add("client_assertion", g.assertion(t, nil))
			return f
		},
		"two assertion types": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, nil))
			f.Add("client_assertion_type", ClientAssertionType)
			return f
		},
		"another assertion type": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, nil))
			f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
			return f
		},
		"no assertion type": func(t *testing.T, g *gateway) url.Values {
			f := g.form(g.subject(t), g.assertion(t, nil))
			f.Del("client_assertion_type")
			return f
		},
		"the mapping registers no key": func(t *testing.T, g *gateway) url.Values {
			g.api.set(func(a *clientAPI) { a.mapping = gatewayMapping(toolsAudience, "") })
			return g.form(g.subject(t), g.assertion(t, nil))
		},
		"an EC assertion under an RSA certificate": func(t *testing.T, g *gateway) url.Values {
			ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			return g.form(g.subject(t), sign(t, jwt.SigningMethodES256, ec, g.claims(nil)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t, toolsAudience)
			rec := exchange(g.handler, "", build(t, g))
			assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			assert.Equal(t, string(CauseClientAssertionInvalid), cause(t, rec))
			assert.NotContains(t, rec.Body.String(), "gateway", "the answer names no service")
			assert.Empty(t, g.records.Records(), "nobody was authenticated")
			g.api.set(func(a *clientAPI) { a.mapping = gatewayMapping(toolsAudience, "gateway-client") })
			require.Equal(t, http.StatusOK, g.exchange(t, g.assertion(t, nil)).Code, "control")
		})
	}
}

// An assertion is used once, by the service it names, and another is fine.
func TestClientAssertionIsUsedOnce(t *testing.T) {
	g := newGateway(t, toolsAudience)
	a := g.assertion(t, nil)
	require.Equal(t, http.StatusOK, g.exchange(t, a).Code)
	rec := g.exchange(t, a)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, string(CauseClientAssertionInvalid), cause(t, rec))
	assert.Equal(t, http.StatusOK, g.exchange(t, g.assertion(t, nil)).Code)

	// One refused for another reason isn't spent: the request can be corrected.
	b := g.assertion(t, nil)
	f := g.form(g.subject(t), b)
	f.Set("client_id", "another")
	require.Equal(t, http.StatusUnauthorized, exchange(g.handler, "", f).Code)
	assert.Equal(t, http.StatusOK, g.exchange(t, b).Code)

	// Concurrent uses of one: exactly one passes.
	c, ok := g.assertion(t, nil), make(chan int, 20)
	var wg sync.WaitGroup
	subject := g.subject(t)
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); ok <- exchange(g.handler, "", g.form(subject, c)).Code }()
	}
	wg.Wait()
	close(ok)
	passed := 0
	for code := range ok {
		if code == http.StatusOK {
			passed++
		}
	}
	assert.Equal(t, 1, passed)
}

// What is remembered is forgotten once it can't verify any more, never before.
func TestSeenJTIs(t *testing.T) {
	var s seenJTIs
	now := time.Now()
	exp := now.Add(time.Minute)
	assert.True(t, s.first("a", exp, now))
	assert.False(t, s.first("a", exp, now))
	assert.True(t, s.first("b", exp, now))
	assert.False(t, s.first("a", exp, exp.Add(assertionLeeway)), "still verifiable")
	assert.Len(t, s.seen, 2)
	assert.True(t, s.first("c", exp.Add(time.Hour), exp.Add(assertionLeeway+time.Second)))
	assert.Len(t, s.seen, 1, "the expired ones are gone")
}

// The key is the registered certificate's, read on every call: rotated, it
// needs nothing else. One that can't be read is authn's failure, which says
// nothing about the Secret.
func TestClientAssertionKey(t *testing.T) {
	g := newGateway(t, toolsAudience)
	old := g.key
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	g.api.set(func(a *clientAPI) { a.secrets["gateway-client"] = validCert(t, rotated) })
	assert.Equal(t, http.StatusUnauthorized, g.exchange(t, g.assertion(t, nil)).Code, "the old key")
	g.key = rotated
	assert.Equal(t, http.StatusOK, g.exchange(t, g.assertion(t, nil)).Code, "the new key")
	_ = old

	key, _ := x509.MarshalPKIXPublicKey(&rotated.PublicKey)
	for name, crt := range map[string][]byte{
		"missing":    nil,
		"empty":      {},
		"not PEM":    []byte("x"),
		"not a cert": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key}),
		"garbage":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
		"expired":    certFor(t, rotated, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)),
		"not yet":    certFor(t, rotated, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			g.api.set(func(a *clientAPI) {
				if a.secrets["gateway-client"] = crt; crt == nil {
					delete(a.secrets, "gateway-client")
				}
			})
			rec := g.exchange(t, g.assertion(t, nil))
			assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
			assert.Equal(t, string(CauseClientKeyUnavailable), cause(t, rec))
			assert.NotContains(t, rec.Body.String(), "gateway-client")
			assert.NotContains(t, rec.Body.String(), "tls.crt", "the answer says nothing about the Secret")
			g.api.set(func(a *clientAPI) { a.secrets["gateway-client"] = validCert(t, rotated) })
			assert.Equal(t, http.StatusOK, g.exchange(t, g.assertion(t, nil)).Code, "control")
		})
	}
	t.Run("the mapping can't be read", func(t *testing.T) {
		g.api.set(func(a *clientAPI) { a.code = http.StatusServiceUnavailable })
		rec := g.exchange(t, g.assertion(t, nil))
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, "MappingLookupFailed", cause(t, rec))
	})
}

// One way to authenticate per route: the assertion's takes no Authorization
// header, and the ServiceAccount token's takes no assertion.
func TestOneAuthenticationPerRoute(t *testing.T) {
	g := newGateway(t, toolsAudience)
	rec := exchange(g.handler, "projected-sa-token", g.form(g.subject(t), g.assertion(t, nil)))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "InvalidRequestBody", cause(t, rec))

	k := newKeys(t)
	rc, calls := apiserver(t, mapping(toolsAudience))
	rec = exchange(k.route(rc), "", g.form(token(t, k.current, "current", time.Hour, nil), g.assertion(t, nil)))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "MissingBearer", cause(t, rec))
	assert.Zero(t, calls.Load())
}

// The mapping decides what an authenticated service may do, as for one
// authenticated by its ServiceAccount token, and the refusal is recorded.
func TestClientAssertionStillNeedsTheMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		delegation, cause string
		code              int
	}{
		"no delegation":        {"", "DelegationNotAllowed", http.StatusForbidden},
		"delegation off":       {`{"allowed":false,"audiences":["tools.krateo-system"]}`, "DelegationNotAllowed", http.StatusForbidden},
		"an unlisted audience": {`{"allowed":true,"audiences":["other.krateo-system"]}`, "InvalidTarget", http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t, tc.delegation)
			rec := g.exchange(t, g.assertion(t, nil))
			assert.Equal(t, tc.code, rec.Code)
			assert.Equal(t, tc.cause, cause(t, rec))
			r := auditlogtest.OnlyAction(t, g.records, auditlog.ActionDelegate)
			assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, "gateway", auditlogtest.String(r, "user.name"))
		})
	}
}

// audienceRequired: no token without an audience.
func TestAudienceRequired(t *testing.T) {
	for _, required := range []bool{true, false} {
		k := newKeys(t)
		rc, _ := apiserver(t, mapping(fmt.Sprintf(`{"allowed":true,"audiences":["tools.krateo-system"],"audienceRequired":%v}`, required)))
		h, records := k.recorded(t, rc)
		f := form(token(t, k.current, "current", time.Hour, nil))
		rec := exchange(h, "projected-sa-token", f)
		if required {
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "InvalidTarget", cause(t, rec))
			r := auditlogtest.OnlyAction(t, records, auditlog.ActionDelegate)
			assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
			f.Set("audience", "")
			assert.Equal(t, http.StatusBadRequest, exchange(h, "projected-sa-token", f).Code, "an empty one isn't an audience")
		} else {
			assert.Equal(t, http.StatusOK, rec.Code)
		}
		f.Set("audience", "tools.krateo-system")
		assert.Equal(t, http.StatusOK, exchange(h, "projected-sa-token", f).Code)
	}
}

// subjectAudiences: a token meant for one service is exchanged only by a
// service it is for. A sign-in's token has no audience, and always is. The
// refusal verified the token, so its record names the person.
func TestSubjectAudiences(t *testing.T) {
	k := newKeys(t)
	subject := func(aud ...string) string {
		tok, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{Username: "alice", Groups: []string{"devs"}, Duration: time.Hour,
			KeyID: "current", PrivateKey: k.current, Principal: jwtutil.PrincipalHuman, Audience: aud})
		require.NoError(t, err)
		return tok
	}
	for name, tc := range map[string]struct {
		mine string
		aud  []string
		ok   bool
	}{
		"a sign-in's token, none listed":      {"", nil, true},
		"a sign-in's token, one listed":       {`"agentiko"`, nil, true},
		"for someone, none listed":            {"", []string{"tools.krateo-system"}, false},
		"for someone else":                    {`"agentiko"`, []string{"tools.krateo-system"}, false},
		"for this service":                    {`"agentiko"`, []string{"agentiko"}, true},
		"for this service and another":        {`"agentiko"`, []string{"tools.krateo-system", "agentiko"}, true},
		"for the second name of this service": {`"a","agentiko"`, []string{"agentiko"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			rc, _ := apiserver(t, mapping(`{"allowed":true,"subjectAudiences":[`+tc.mine+`]}`))
			h, records := k.recorded(t, rc)
			rec := exchange(h, "projected-sa-token", form(subject(tc.aud...)))
			r := auditlogtest.OnlyAction(t, records, auditlog.ActionDelegate)
			assert.Equal(t, "alice", auditlogtest.String(r, "krateo.audit.on_behalf_of.user.name"))
			if tc.ok {
				_, nfo := issued(t, k, rec)
				assert.Equal(t, "alice", nfo.Username)
				var payload map[string]any
				raw, err := base64.RawURLEncoding.DecodeString(strings.Split(mustToken(t, rec), ".")[1])
				require.NoError(t, err)
				require.NoError(t, json.Unmarshal(raw, &payload))
				assert.NotContains(t, payload, "aud", "the issued token's audience is the one asked for, never the subject's")
				return
			}
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, "SubjectAudienceNotAllowed", cause(t, rec))
			assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, "subject_token_invalid", auditlogtest.String(r, "krateo.audit.denial_reason"))
			assert.NotContains(t, rec.Body.String(), "alice")
		})
	}
}

func mustToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out exchanged
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out.AccessToken
}
