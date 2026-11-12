package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/krateo-platformops/authn/internal/logtest"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// Every way an OAuth login fails before an identity exists answers a code
// that says whose failure it is and a cause that says which one, keeps the
// provider's error_description out of the answer (and the log: only the error
// code is repeated), and mints nothing.
func TestLoginFailuresCarryCauses(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	type answer struct {
		code int
		body string
	}
	cases := []struct {
		name      string
		query     string
		code      string
		config    *answer // nil: the OAuthConfig
		secret    *answer // nil: the client secret
		token     *answer // nil: the token endpoint must not be called
		wantCode  int
		wantCause string
		noAPICall bool
		notInBody string
	}{
		{name: "no name", query: "", code: "c", wantCode: 400, wantCause: "MissingConfigName", noAPICall: true},
		{name: "no code", query: "?name=gh", wantCode: 400, wantCause: "MissingAuthorizationCode", noAPICall: true},
		{name: "no such config", query: "?name=gh", code: "c", config: &answer{404, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":404}`},
			wantCode: 404, wantCause: "OAuthConfigNotFound"},
		{name: "a name no config can have", query: "?name=" + url.QueryEscape("a/b"), code: "c", wantCode: 404, wantCause: "OAuthConfigNotFound", noAPICall: true},
		{name: "apiserver failing", query: "?name=gh", code: "c", config: &answer{500, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":500}`},
			wantCode: 500, wantCause: "OAuthConfigLookupFailed"},
		{name: "client secret unreadable", query: "?name=gh", code: "c", secret: &answer{403, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":403}`},
			wantCode: 500, wantCause: "ClientSecretLookupFailed"},
		{name: "client secret without the key", query: "?name=gh", code: "c",
			secret:   &answer{200, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"gh","namespace":"krateo-system"},"data":{}}`},
			wantCode: 500, wantCause: "ClientSecretLookupFailed"},
		{name: "code refused (RFC 6749)", query: "?name=gh", code: "c",
			token:    &answer{400, `{"error":"invalid_grant","error_description":"zz-sentinel-idp-detail"}`},
			wantCode: 403, wantCause: "AuthorizationCodeRejected", notInBody: "zz-sentinel-idp-detail"},
		{name: "code refused (GitHub answers 200)", query: "?name=gh", code: "c",
			token:    &answer{200, `{"error":"bad_verification_code","error_description":"zz-sentinel-idp-detail"}`},
			wantCode: 403, wantCause: "AuthorizationCodeRejected", notInBody: "zz-sentinel-idp-detail"},
		{name: "client credentials refused", query: "?name=gh", code: "c",
			token:    &answer{401, `{"error":"invalid_client","error_description":"zz-sentinel-idp-detail"}`},
			wantCode: 500, wantCause: "TokenExchangeFailed", notInBody: "zz-sentinel-idp-detail"},
		{name: "token endpoint failing", query: "?name=gh", code: "c",
			token:    &answer{502, `<html>zz-sentinel-idp-detail</html>`},
			wantCode: 500, wantCause: "TokenExchangeFailed", notInBody: "zz-sentinel-idp-detail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			asked := false
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				reply := func(a *answer, def string) {
					if a == nil {
						_, _ = io.WriteString(w, def)
						return
					}
					w.WriteHeader(a.code)
					_, _ = io.WriteString(w, a.body)
				}
				switch r.URL.Path {
				case "/token":
					if tc.token == nil {
						t.Error("the token endpoint was called, though the login had already failed")
					}
					reply(tc.token, `{}`)
				case "/apis/oauth.authn.krateo.io/v1alpha1/namespaces/krateo-system/oauthconfigs/gh":
					asked = true
					reply(tc.config, fmt.Sprintf(`{"apiVersion":"oauth.authn.krateo.io/v1alpha1","kind":"OAuthConfig","metadata":{"name":"gh","namespace":"krateo-system"},
						"spec":{"clientID":"portal","clientSecretRef":{"name":"gh","namespace":"krateo-system","key":"clientSecret"},
						"authURL":"%[1]s/auth","tokenURL":"%[1]s/token","redirectURL":"https://portal.example/auth","scopes":["user"]}}`, srv.URL))
				case "/api/v1/namespaces/krateo-system/secrets/gh":
					asked = true
					reply(tc.secret, fmt.Sprintf(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"gh","namespace":"krateo-system"},"data":{"clientSecret":%q}}`,
						base64.StdEncoding.EncodeToString([]byte("s3cret"))))
				default:
					asked = true
					t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			gen := &fakeGenerator{}
			route := Login(t.Context(), &rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})
			req, logs := logtest.Request(httptest.NewRequest(http.MethodGet, Path+tc.query, nil))
			if tc.code != "" {
				req.Header.Set("X-Auth-Code", tc.code)
			}
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)
			// The IdP's answers carry logtest.Marker: only the error code is logged.
			logtest.NoIdentity(t, logs)

			require.Equal(t, tc.wantCode, rec.Code, rec.Body.String())
			var st struct {
				Status  string `json:"status"`
				Code    int    `json:"code"`
				Details struct {
					Causes []struct {
						Reason string `json:"reason"`
					} `json:"causes"`
				} `json:"details"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &st), rec.Body.String())
			assert.Equal(t, "Failure", st.Status)
			assert.Equal(t, tc.wantCode, st.Code)
			require.Len(t, st.Details.Causes, 1, rec.Body.String())
			assert.Equal(t, tc.wantCause, st.Details.Causes[0].Reason)
			assert.Zero(t, gen.calls, "nothing minted")
			if tc.noAPICall {
				assert.False(t, asked, "answered before looking anything up")
			}
			if tc.notInBody != "" {
				assert.NotContains(t, rec.Body.String(), tc.notInBody, "the provider's answer isn't repeated to the caller")
			}
		})
	}
}
