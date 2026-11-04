package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The code exchange carries the client secret, the code and any PKCE
// verifier, so a redirect from the token endpoint is refused: 500
// TokenExchangeFailed, and the redirect target never hears from authn.
func TestTokenEndpointRedirectIsRefused(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	reached := 0
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++ }))
	t.Cleanup(dest.Close)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			http.Redirect(w, r, dest.URL+"/steal", http.StatusTemporaryRedirect)
		case "/apis/oauth.authn.krateo.io/v1alpha1/namespaces/krateo-system/oauthconfigs/gh":
			fmt.Fprintf(w, `{"apiVersion":"oauth.authn.krateo.io/v1alpha1","kind":"OAuthConfig","metadata":{"name":"gh","namespace":"krateo-system"},
				"spec":{"clientID":"portal","clientSecretRef":{"name":"gh","namespace":"krateo-system","key":"clientSecret"},
				"authURL":"%[1]s/auth","tokenURL":"%[1]s/token","redirectURL":"https://portal.example/auth","scopes":["user"]}}`, srv.URL)
		case "/api/v1/namespaces/krateo-system/secrets/gh":
			fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"gh","namespace":"krateo-system"},"data":{"clientSecret":%q}}`,
				base64.StdEncoding.EncodeToString([]byte("s3cret")))
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	gen := &fakeGenerator{}
	route := Login(t.Context(), &rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})
	req := httptest.NewRequest(http.MethodGet, Path+"?name=gh", nil)
	req.Header.Set("X-Auth-Code", "code")
	req.Header.Set("X-Code-Verifier", "verifier")
	rec := httptest.NewRecorder()
	route.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	var st struct {
		Details struct {
			Causes []struct {
				Reason string `json:"reason"`
			} `json:"causes"`
		} `json:"details"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &st))
	require.Len(t, st.Details.Causes, 1)
	assert.Equal(t, "TokenExchangeFailed", st.Details.Causes[0].Reason)
	assert.Zero(t, gen.calls)
	assert.Zero(t, reached, "the client secret, code and verifier never left for the redirect target")
}
