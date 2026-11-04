package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The PKCE verifier the client sends in X-Code-Verifier reaches the token
// endpoint as code_verifier (RFC 7636 §4.5), and none is sent without it: an
// IdP that got a code_challenge refuses an exchange without its verifier.
func TestLoginForwardsTheCodeVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for name, verifier := range map[string]string{
		"with PKCE":    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"without PKCE": "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			var sent []string
			exchanged := false
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/token":
					require.NoError(t, r.ParseForm())
					exchanged = true
					sent = r.PostForm["code_verifier"]
					assert.Equal(t, "the-code", r.PostForm.Get("code"))
					_, _ = io.WriteString(w, `{"access_token":"at","token_type":"bearer"}`)
				case "/apis/oauth.authn.krateo.io/v1alpha1/namespaces/krateo-system/oauthconfigs/gh":
					fmt.Fprintf(w, `{"apiVersion":"oauth.authn.krateo.io/v1alpha1","kind":"OAuthConfig","metadata":{"name":"gh","namespace":"krateo-system"},
						"spec":{"clientID":"portal","clientSecretRef":{"name":"gh","namespace":"krateo-system","key":"clientSecret"},
						"authURL":"%[1]s/auth","tokenURL":"%[1]s/token","redirectURL":"https://portal.example/auth","scopes":["user"]}}`, srv.URL)
				case "/api/v1/namespaces/krateo-system/secrets/gh":
					fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"gh","namespace":"krateo-system"},"data":{"clientSecret":%q}}`,
						base64.StdEncoding.EncodeToString([]byte("s3cret")))
				default:
					t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			gen := &fakeGenerator{}
			route := Login(t.Context(), &rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})
			req := httptest.NewRequest(http.MethodGet, Path+"?name=gh", nil)
			req.Header.Set("X-Auth-Code", "the-code")
			if verifier != "" {
				req.Header.Set("X-Code-Verifier", verifier)
			}
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.True(t, exchanged, rec.Body.String())
			if verifier == "" {
				assert.Empty(t, sent, "no code_verifier without PKCE")
			} else {
				assert.Equal(t, []string{verifier}, sent)
			}
		})
	}
}
