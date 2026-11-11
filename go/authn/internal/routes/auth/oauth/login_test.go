package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

type fakeGenerator struct {
	// records holds what the route's audit Recorder wrote (AUDIT-4).
	records *audittest.Recorder
	calls   int
	info    userinfo.Info // the identity of the last Generate
}

func (g *fakeGenerator) Generate(_ storage.Strategy, nfo userinfo.Info, _ ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	g.calls++
	g.info = nfo
	return kubeconfig.Issued{Kubeconfig: []byte(`{}`), NotAfter: time.Now().Add(time.Hour), Secret: auditlogtest.Created(nfo.GetUserName())}, nil
}

func (g *fakeGenerator) GenerateStepUp(storage.Strategy, userinfo.Info, time.Duration, ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	panic("oauth login never issues a step-up credential")
}

// When the RESTAction's answer can't be parsed into an identity, the login
// answers 500 once and stops: it mints nothing and writes no second response.
func TestLoginStopsWhenTheRESTActionAnswerIsUnusable(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")

	// snowplow resolves the RESTAction to a name and a groups that isn't a list.
	snowplow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":{"subject":"1001","name":"Alice","preferredUsername":"alice","groups":"devs"}}`)
	}))
	t.Cleanup(snowplow.Close)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token": // the provider's token endpoint
			_, _ = io.WriteString(w, `{"access_token":"at","token_type":"bearer"}`)
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

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	gen := &fakeGenerator{}
	route := Login(base, &rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})

	req := httptest.NewRequest(http.MethodGet, Path+"?name=gh", nil)
	req.Header.Set("X-Auth-Code", "code")
	rec := httptest.NewRecorder()
	route.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Zero(t, gen.calls, "no credential is minted for an identity that couldn't be built")

	dec := json.NewDecoder(rec.Body)
	var out struct {
		Kind string `json:"kind"`
		Code int    `json:"code"`
	}
	require.NoError(t, dec.Decode(&out))
	assert.Equal(t, "Status", out.Kind)
	assert.Equal(t, http.StatusInternalServerError, out.Code)
	assert.ErrorIs(t, dec.Decode(&struct{}{}), io.EOF, "exactly one response is written")
}
