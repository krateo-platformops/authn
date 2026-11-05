package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// RFC 6749 §7.1: token_type is case-insensitive. An IdP answering "Bearer"
// signs the user in like one answering "bearer"; any other type is refused
// before its token reaches the RESTAction.
func TestLoginAcceptsTheBearerTypeInAnyCase(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for tokenType, wantCode := range map[string]int{
		"bearer": http.StatusOK,
		"Bearer": http.StatusOK,
		"BEARER": http.StatusOK,
		"mac":    http.StatusInternalServerError,
	} {
		t.Run(tokenType, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			snowplowCalled := false
			snowplow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				snowplowCalled = true
				_, _ = io.WriteString(w, `{"status":{"name":"Alice","preferredUsername":"alice","groups":["devs"]}}`)
			}))
			t.Cleanup(snowplow.Close)

			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/token":
					fmt.Fprintf(w, `{"access_token":"at","token_type":%q}`, tokenType)
				case "/apis/oauth.authn.krateo.io/v1alpha1/namespaces/krateo-system/oauthconfigs/gh":
					fmt.Fprintf(w, `{"apiVersion":"oauth.authn.krateo.io/v1alpha1","kind":"OAuthConfig","metadata":{"name":"gh","namespace":"krateo-system"},
						"spec":{"clientID":"portal","clientSecretRef":{"name":"gh","namespace":"krateo-system","key":"clientSecret"},
						"authURL":"%[1]s/auth","tokenURL":"%[1]s/token","redirectURL":"https://portal.example/auth","scopes":["user"],
						"restActionRef":{"name":"userinfo","namespace":"krateo-system"}}}`, srv.URL)
				case "/api/v1/namespaces/krateo-system/secrets/gh":
					fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"gh","namespace":"krateo-system"},"data":{"clientSecret":%q}}`,
						base64.StdEncoding.EncodeToString([]byte("s3cret")))
				default:
					t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			base := xcontext.BuildContext(context.Background(), xcontext.WithAccessToken("authn-token"))
			base = context.WithValue(base, restaction.RestActionContextKey("snowplowURL"), snowplow.URL)
			gen := &fakeGenerator{}
			route := Login(base, &rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})
			req := httptest.NewRequest(http.MethodGet, Path+"?name=gh", nil)
			req.Header.Set("X-Auth-Code", "code")
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, wantCode, rec.Code, rec.Body.String())
			if wantCode == http.StatusOK {
				assert.True(t, snowplowCalled)
				assert.Equal(t, 1, gen.calls)
				assert.Contains(t, rec.Body.String(), `"strategy":{"kind":"oauth","name":"gh"}`)
			} else {
				assert.False(t, snowplowCalled, "a non-bearer token never reaches the RESTAction")
				assert.Zero(t, gen.calls)
			}
		})
	}
}
