package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The public surface: every route authn serves. A new route makes
// TestPublicSurface fail until it is added here, which is the point: each one
// must be reviewed for what it answers without a successful login.
var publicSurface = []string{
	"GET /.well-known/jwks.json",
	"GET /basic/login",
	"GET /health",
	"GET /oauth/login",
	"GET /oidc/login",
	"GET /strategies",
	"POST /ldap/login",
	"POST /oidc/stepup",
	"POST /serviceaccount/login",
}

// Canaries: every Secret the fake apiserver serves carries these in every key,
// as stored credentials, passwords and client secrets would. They are fake
// by design; the gitleaks:allow markers tell the secret scanner so.
const (
	canaryKey    = "-----BEGIN RSA PRIVATE KEY-----CANARY-KEY-7f3a-----END RSA PRIVATE KEY-----" // gitleaks:allow
	canaryCert   = "CANARY-CERT-1c9e"
	canarySecret = "CANARY-SECRET-b52d" // gitleaks:allow
)

// mintCounter fails the test's expectations if anything is minted: no request
// without a successful login may issue a credential.
type mintCounter struct{ calls atomic.Int32 }

func (g *mintCounter) Generate(_ storage.Strategy, _ userinfo.Info) ([]byte, time.Time, error) {
	g.calls.Add(1)
	return []byte(`{}`), time.Now().Add(time.Hour), nil
}

func (g *mintCounter) GenerateStepUp(_ storage.Strategy, _ userinfo.Info, _ time.Duration) (time.Time, error) {
	g.calls.Add(1)
	return time.Now().Add(time.Hour), nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// fakeAPIServer serves one object of every authn kind, named "kc" (users:
// "admin"), each pointing at Secrets full of canaries, and refuses every
// TokenReview. The same server is the IdP's token endpoint, which rejects
// every code.
func fakeAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	ref := `{"name":"creds","namespace":"krateo-system","key":"password"}`
	specs := map[string][3]string{ // plural -> apiVersion, kind, spec
		"users":           {"basic.authn.krateo.io/v1alpha1", "User", `{"passwordRef":` + ref + `,"displayName":"Admin","groups":["admins"]}`},
		"serviceaccounts": {"serviceaccount.authn.krateo.io/v1alpha1", "ServiceAccount", `{"serviceAccountRef":{"namespace":"krateo-system","name":"cdc"},"groups":["svc"]}`},
		"ldapconfigs":     {"ldap.authn.krateo.io/v1alpha1", "LDAPConfig", `{"dialURL":"ldap://127.0.0.1:1","baseDN":"dc=example","bindDN":"cn=admin","bindSecret":` + ref + `}`},
	}
	dynamicSpecs := func() map[string][3]string {
		m := map[string][3]string{}
		for k, v := range specs {
			m[k] = v
		}
		m["oauthconfigs"] = [3]string{"oauth.authn.krateo.io/v1alpha1", "OAuthConfig",
			`{"clientID":"portal","clientSecretRef":` + ref + `,"authURL":"` + srv.URL + `/auth","tokenURL":"` + srv.URL + `/token","redirectURL":"https://portal.example/auth","scopes":["openid"]}`}
		m["oidcconfigs"] = [3]string{"oidc.authn.krateo.io/v1alpha1", "OIDCConfig",
			`{"issuer":"` + srv.URL + `","authorizationURL":"` + srv.URL + `/auth","tokenURL":"` + srv.URL + `/token","redirectURI":"https://portal.example/auth","clientID":"portal","clientSecret":` + ref + `,"stepUp":{"acrValues":["gold"]}}`}
		return m
	}

	secret := func(name string) string {
		data := map[string]string{}
		for _, k := range []string{storage.ClientKeyLabel, storage.ClientCertLabel, storage.CALabel, storage.ServerUrlLabel, storage.ProxyUrlLabel, "password", "clientSecret", "private.pem"} {
			v := canarySecret
			switch k {
			case storage.ClientKeyLabel, "private.pem":
				v = canaryKey
			case storage.ClientCertLabel:
				v = canaryCert
			}
			data[k] = b64(v)
		}
		out, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Secret",
			"metadata": map[string]any{"name": name, "namespace": "krateo-system"}, "data": data})
		return string(out)
	}

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case r.URL.Path == "/token": // the IdP rejects every code
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		case strings.HasSuffix(r.URL.Path, "/tokenreviews"):
			_, _ = io.WriteString(w, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",`+
				`"status":{"authenticated":false,"error":"token is not valid"}}`)
		case len(seg) >= 5 && seg[0] == "api" && seg[4] == "secrets":
			if len(seg) == 6 {
				_, _ = io.WriteString(w, secret(seg[5]))
				return
			}
			_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"SecretList","metadata":{},"items":[`+secret("admin-clientconfig")+`,`+secret("authn-clientconfig")+`]}`)
		case seg[0] == "apis":
			for plural, s := range dynamicSpecs() {
				i := indexOf(seg, plural)
				if i < 0 {
					continue
				}
				name := "kc"
				if plural == "users" {
					name = "admin"
				}
				obj := fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"name":%q,"namespace":"krateo-system"},"spec":%s}`, s[0], s[1], name, s[2])
				if i == len(seg)-1 {
					_, _ = fmt.Fprintf(w, `{"apiVersion":%q,"kind":%q,"metadata":{},"items":[%s]}`, s[0], s[1]+"List", obj)
					return
				}
				_, _ = io.WriteString(w, obj)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func indexOf(seg []string, s string) int {
	for i, x := range seg {
		if x == s {
			return i
		}
	}
	return -1
}

func publicRoutes(t *testing.T, gen *mintCounter) []routes.Route {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	healthy := int32(1)
	all, err := buildRoutes(routeOptions{
		RestConfig:             &rest.Config{Host: fakeAPIServer(t).URL},
		Generator:              gen,
		PrivateKey:             key,
		KeyID:                  "k",
		JwtDuration:            time.Hour,
		ServiceAccountAudience: "authn",
		SelfUsername:           "authn",
		SnowplowURL:            "http://127.0.0.1:1",
		Healthy:                &healthy,
		Version:                "test",
		ServiceName:            "authn",
	})
	require.NoError(t, err)
	return all
}

// TestPublicSurface pins authn's HTTP surface and checks that no request
// without a successful login gets key material, a stored credential or a
// secret back, or makes authn mint a credential.
func TestPublicSurface(t *testing.T) {
	gen := &mintCounter{}
	all := publicRoutes(t, gen)

	var got []string
	for _, r := range all {
		got = append(got, r.Method()+" "+r.Pattern())
	}
	sort.Strings(got)
	require.Equal(t, publicSurface, got, "the HTTP surface changed: review the new route, then update publicSurface")

	found, n := probe(routes.Serve(all, testLogger()))
	assert.Empty(t, found, "a request without a successful login got something it must not")
	t.Logf("%d unauthenticated requests checked", n)
	assert.Zero(t, gen.calls.Load(), "a credential was minted for a request without a successful login")
}

// The guard catches a leak: a route returning a stored credential to any
// caller is flagged.
func TestPublicSurfaceGuardCatchesALeak(t *testing.T) {
	all := publicRoutes(t, &mintCounter{})
	all = append(all, leakyRoute{})
	found, _ := probe(routes.Serve(all, testLogger()))
	assert.NotEmpty(t, found, "the guard missed a route that returns a stored private key")
}

// leakyRoute returns a stored credential to any caller.
type leakyRoute struct{}

func (leakyRoute) Name() string    { return "leaky" }
func (leakyRoute) Pattern() string { return "/leaky" }
func (leakyRoute) Method() string  { return http.MethodGet }
func (leakyRoute) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{storage.ClientKeyLabel: canaryKey})
	}
}

// probe sends every route, under every method, the inputs a caller without
// valid credentials can send: nothing, wrong or junk credentials, and the
// names of real identities. It returns what leaked, and how many requests it
// sent.
func probe(handler http.Handler) ([]string, int) {
	leaks := []string{canaryKey, canaryCert, canarySecret, "CANARY", "PRIVATE KEY",
		b64(canaryKey), b64(canaryCert), b64(canarySecret), storage.ClientKeyLabel}
	paths := []string{"/strategies", "/health", "/.well-known/jwks.json", "/basic/login", "/ldap/login",
		"/oauth/login", "/oidc/login", "/oidc/stepup", "/serviceaccount/login", "/info", "/leaky"}
	queries := []string{"", "?name=kc", "?name=admin", "?name=authn", "?name=admin&d", "?d"}
	headers := []map[string]string{
		{},
		{"Authorization": "Basic " + b64("admin:wrong")},
		{"Authorization": "Basic " + b64("admin:")},
		{"Authorization": "Basic " + b64("authn:wrong")},
		{"Authorization": "Bearer not-a-token"},
		{"X-Auth-Code": "junk", "X-Code-Verifier": "junk"},
	}
	body := `{"username":"admin","password":"wrong"}`

	var found []string
	n := 0
	for _, p := range paths {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			for _, q := range queries {
				for _, h := range headers {
					req := httptest.NewRequest(m, p+q, strings.NewReader(body))
					for k, v := range h {
						req.Header.Set(k, v)
					}
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					n++

					where := fmt.Sprintf("%s %s%s %v -> %d", m, p, q, h, rec.Code)
					for _, l := range leaks {
						if strings.Contains(rec.Body.String(), l) {
							found = append(found, fmt.Sprintf("%s: body contains %q", where, l))
						}
						for k, vs := range rec.Header() {
							if strings.Contains(strings.Join(vs, ","), l) {
								found = append(found, fmt.Sprintf("%s: header %s contains %q", where, k, l))
							}
						}
					}
					if p == "/info" && rec.Code != http.StatusNotFound {
						found = append(found, where+": /info is served")
					}
				}
			}
		}
	}
	return found, n
}

// The JWKS publishes the public half of the signing key only.
func TestJWKSIsPublicOnly(t *testing.T) {
	handler := routes.Serve(publicRoutes(t, &mintCounter{}), testLogger())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &set))
	require.Len(t, set.Keys, 1)
	for k := range set.Keys[0] {
		assert.Contains(t, []string{"kty", "use", "alg", "kid", "n", "e"}, k, "JWKS member %q", k)
	}
}

func testLogger() zerolog.Logger { return zerolog.Nop() }
