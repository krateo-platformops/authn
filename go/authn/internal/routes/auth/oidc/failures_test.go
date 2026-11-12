package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/krateo-platformops/authn/internal/logtest"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// failureEnv serves one OIDCConfig named kc whose token endpoint answers with
// token, and an apiserver that answers api (nil: the OIDCConfig). It records
// whether the apiserver was asked at all.
func failureEnv(t *testing.T, extraSpec string, api, token http.HandlerFunc) (*rest.Config, *bool) {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")

	idp := httptest.NewServer(token)
	t.Cleanup(idp.Close)

	spec := `"issuer":"` + testIssuer + `","authorizationURL":"https://idp.example/auth","tokenURL":"` + idp.URL + `",
		"redirectURI":"https://portal.example/auth","clientID":"portal"`
	if extraSpec != "" {
		spec += `,` + extraSpec
	}
	asked := new(bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*asked = true
		if api != nil {
			api(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"oidc.authn.krateo.io/v1alpha1","kind":"OIDCConfig",
			"metadata":{"name":"kc","namespace":"krateo-system"},"spec":{` + spec + `}}`))
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}, asked
}

func tokenAnswer(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

func apiAnswer(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":%d}`, code)
	}
}

// answer runs one request against /oidc/login (or /oidc/stepup) and decodes
// the Status it answered.
func answer(t *testing.T, rc *rest.Config, stepUp bool, query string, code string) (*httptest.ResponseRecorder, *stepUpGenerator) {
	t.Helper()
	key := failureKey(t)
	gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}

	var h http.HandlerFunc
	path := Path
	if stepUp {
		h = StepUp(t.Context(), rc, StepUpOptions{KubeconfigGenerator: gen, JwtPrivateKey: key, JwtKeyID: "k"}).Handler()
		path = StepUpPath
	} else {
		h = Login(t.Context(), rc, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"}).Handler()
	}
	req, logs := logtest.Request(httptest.NewRequest(http.MethodGet, path+query, nil))
	if code != "" {
		req.Header.Set("X-Auth-Code", code)
	}
	req.Header.Set("X-Code-Verifier", testCodeVerifier)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// The IdP's answers carry logtest.Marker: an error_description or body
	// that names the user never reaches a log line, only the error code.
	logtest.NoIdentityIfAny(t, logs)
	return rec, gen
}

// failureKey is one signing key for every failure case: none of them signs.
var failureKey = func() func(*testing.T) *rsa.PrivateKey {
	var once sync.Once
	var key *rsa.PrivateKey
	var err error
	return func(t *testing.T) *rsa.PrivateKey {
		once.Do(func() { key, err = rsa.GenerateKey(rand.Reader, 2048) })
		require.NoError(t, err)
		return key
	}
}()

type statusBody struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    int    `json:"code"`
	Details struct {
		Causes []struct {
			Reason string `json:"reason"`
		} `json:"causes"`
	} `json:"details"`
}

func decodeStatus(t *testing.T, rec *httptest.ResponseRecorder) statusBody {
	t.Helper()
	var st statusBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &st), rec.Body.String())
	assert.Equal(t, "Failure", st.Status, "every refusal and failure says so in its body")
	assert.Equal(t, rec.Code, st.Code)
	require.Len(t, st.Details.Causes, 1, rec.Body.String())
	return st
}

// Every way an OIDC login fails answers a code that says whose failure it is
// and a cause that says which one, and none of them mints a credential.
func TestLoginFailuresCarryCauses(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	discovery503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(discovery503.Close)

	cases := []struct {
		name      string
		extraSpec string
		api       http.HandlerFunc
		token     http.HandlerFunc
		query     string
		code      string
		wantCode  int
		wantCause string
		noAPICall bool
		notInBody string
	}{
		{name: "no name", query: "", code: "c", wantCode: 400, wantCause: "MissingConfigName", noAPICall: true},
		{name: "no code", query: "?name=kc", code: "", wantCode: 400, wantCause: "MissingAuthorizationCode", noAPICall: true},
		{name: "no such config", api: apiAnswer(404), query: "?name=kc", code: "c", wantCode: 404, wantCause: "OIDCConfigNotFound"},
		{name: "a name no config can have", query: "?name=" + url.QueryEscape("a/b"), code: "c", wantCode: 404, wantCause: "OIDCConfigNotFound", noAPICall: true},
		{name: "apiserver failing", api: apiAnswer(500), query: "?name=kc", code: "c", wantCode: 500, wantCause: "OIDCConfigLookupFailed"},
		{name: "discovery failing", extraSpec: `"discoveryURL":"` + discovery503.URL + `"`, query: "?name=kc", code: "c", wantCode: 500, wantCause: "OIDCDiscoveryFailed"},
		{name: "code refused", token: tokenAnswer(400, `{"error":"invalid_grant","error_description":"zz-sentinel-idp-detail"}`),
			query: "?name=kc", code: "c", wantCode: 403, wantCause: "AuthorizationCodeRejected", notInBody: "zz-sentinel-idp-detail"},
		{name: "client credentials refused", token: tokenAnswer(401, `{"error":"invalid_client","error_description":"zz-sentinel-idp-detail"}`),
			query: "?name=kc", code: "c", wantCode: 500, wantCause: "TokenExchangeFailed", notInBody: "zz-sentinel-idp-detail"},
		{name: "token endpoint failing", token: tokenAnswer(502, `<html>zz-sentinel-idp-detail</html>`),
			query: "?name=kc", code: "c", wantCode: 500, wantCause: "TokenExchangeFailed", notInBody: "zz-sentinel-idp-detail"},
		{name: "a 200 that isn't JSON", token: tokenAnswer(200, `<html>zz-sentinel-idp-detail</html>`),
			query: "?name=kc", code: "c", wantCode: 500, wantCause: "TokenExchangeFailed", notInBody: "zz-sentinel-idp-detail"},
		{name: "token endpoint unreachable", extraSpec: `"tokenURL":"` + closedURL + `"`,
			query: "?name=kc", code: "c", wantCode: 500, wantCause: "TokenExchangeFailed", notInBody: closedURL},
	}
	for _, tc := range cases {
		for _, stepUp := range []bool{false, true} {
			name := tc.name
			if stepUp {
				name += "/stepup"
			}
			t.Run(name, func(t *testing.T) {
				token := tc.token
				if token == nil {
					token = func(w http.ResponseWriter, r *http.Request) {
						t.Error("the token endpoint was called, though the login had already failed")
						http.Error(w, "unexpected", http.StatusTeapot)
					}
				}
				extra := tc.extraSpec
				if stepUp {
					if extra != "" {
						extra += ","
					}
					extra += `"stepUp":` + stepUpGold
				}
				rc, asked := failureEnv(t, extra, tc.api, token)

				rec, gen := answer(t, rc, stepUp, tc.query, tc.code)
				require.Equal(t, tc.wantCode, rec.Code, rec.Body.String())
				st := decodeStatus(t, rec)
				assert.Equal(t, tc.wantCause, st.Details.Causes[0].Reason)
				assert.Empty(t, gen.sessions, "nothing minted")
				assert.Empty(t, gen.stepUps, "nothing minted")
				if tc.noAPICall {
					assert.False(t, *asked, "answered before looking anything up")
				}
				if tc.notInBody != "" {
					assert.NotContains(t, rec.Body.String(), tc.notInBody, "the IdP's answer and authn's endpoints aren't repeated to the caller")
				}
			})
		}
	}
}
