package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krateo-platformops/audit"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/logtest/gentest"
	"github.com/krateo-platformops/authn/internal/status"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// oauthLogin runs one OAuth login whose RESTAction answers answer. restAction
// false configures the OAuthConfig without a restActionRef.
func oauthLogin(t *testing.T, answer string, restAction bool) (*httptest.ResponseRecorder, *fakeGenerator) {
	t.Helper()
	gen := &fakeGenerator{}
	rec, _ := oauthLoginWith(t, answer, restAction, gen)
	return rec, gen
}

// oauthLoginWith is oauthLogin with gen issuing, and the route's log lines.
func oauthLoginWith(t *testing.T, answer string, restAction bool, gen *fakeGenerator) (*httptest.ResponseRecorder, *logtest.Buffer) {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	snowplow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(snowplow.Close)

	ref := `,"restActionRef":{"name":"userinfo","namespace":"krateo-system"}`
	if !restAction {
		ref = ""
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = io.WriteString(w, `{"access_token":"at","token_type":"bearer"}`)
		case "/apis/oauth.authn.krateo.io/v1alpha1/namespaces/krateo-system/oauthconfigs/gh":
			fmt.Fprintf(w, `{"apiVersion":"oauth.authn.krateo.io/v1alpha1","kind":"OAuthConfig","metadata":{"name":"gh","namespace":"krateo-system"},
				"spec":{"clientID":"portal","clientSecretRef":{"name":"gh","namespace":"krateo-system","key":"clientSecret"},
				"authURL":"%[1]s/auth","tokenURL":"%[1]s/token","redirectURL":"https://portal.example/auth","scopes":["user"]%[2]s}}`, srv.URL, ref)
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
	audit, records := auditlogtest.New(t)
	gen.records = records
	route := Login(base, &rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gentest.Generator{Generator: gen, T: t}, Audit: audit, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})
	req, logs := logtest.Request(httptest.NewRequest(http.MethodGet, Path+"?name=gh", nil))
	req.Header.Set("X-Auth-Code", "code")
	rec := httptest.NewRecorder()
	auditlog.Middleware(route.Handler()).ServeHTTP(rec, req)
	return rec, logs
}

// The identity issued is named by the provider's stable id, which the
// RESTAction answers as `subject`, issued by the OAuthConfig: a GitHub user who
// takes over a renamed login is a different identity.
func TestLoginNamesTheSubject(t *testing.T) {
	rec, gen := oauthLogin(t, `{"status":{"subject":"1001","name":"Alice","preferredUsername":"Alice","groups":["devs"]}}`, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 1, gen.calls)
	assert.Equal(t, "alice", gen.info.GetUserName())
	assert.Equal(t, userinfo.Subject{Issuer: "gh", ID: "1001"}, gen.info.GetSubject())
	// One conformant record, the callback's query (code, state) dropped (AUDIT-4).
	r := auditlogtest.Only(t, gen.records)
	assert.Equal(t, "authn.login.oauth", auditlogtest.String(r, "krateo.action"))
	assert.Equal(t, "/oauth/login?name=gh", auditlogtest.String(r, "krateo.request.uri"), "a callback keeps name, never code or state")
}

// Without a subject, authn can't tell this user from one who takes the same
// login later, so it issues nothing: 500 RESTActionIdentityInvalid, for an
// administrator to fix the RESTAction. The same goes for an OAuthConfig with no
// RESTAction, which identifies no one.
func TestLoginWithoutASubjectIssuesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		answer     string
		restAction bool
	}{
		"no subject":      {`{"status":{"name":"Alice","preferredUsername":"alice"}}`, true},
		"empty subject":   {`{"status":{"subject":"","name":"Alice","preferredUsername":"alice"}}`, true},
		"numeric subject": {`{"status":{"subject":1001,"name":"Alice","preferredUsername":"alice"}}`, true},
		"no RESTAction":   {``, false},
	} {
		t.Run(name, func(t *testing.T) {
			rec, gen := oauthLogin(t, tc.answer, tc.restAction)
			assert.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.Contains(t, rec.Body.String(), `"reason":"RESTActionIdentityInvalid"`,
				"an answer that can't identify anyone is for an administrator, not a retry")
			assert.Zero(t, gen.calls, "nothing is issued")
		})
	}
}

// A RESTAction that couldn't be resolved is RESTActionFailed, for a retry, not
// RESTActionIdentityInvalid: here snowplow answers something that isn't JSON.
func TestAnUnresolvedRESTActionIsRESTActionFailed(t *testing.T) {
	rec, gen := oauthLogin(t, `not json`, true)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"reason":"RESTActionFailed"`)
	assert.NotContains(t, rec.Body.String(), "RESTActionIdentityInvalid")
	assert.Zero(t, gen.calls, "nothing is issued")
}

// A verified identity whose Secret write fails is one failure record,
// conformant, naming the Secret, the create sent and the apiserver's answer
// (AUDIT-4).
func TestLoginIssuanceFailureIsRecorded(t *testing.T) {
	gen := &fakeGenerator{err: errors.New("creating the session Secret: InternalError (500)"),
		written: auditlogtest.WriteFailed("alice", http.StatusInternalServerError)}
	rec, _ := oauthLoginWith(t, `{"status":{"subject":"1001","name":"Alice","preferredUsername":"alice","groups":["devs"]}}`, true, gen)
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	require.Equal(t, 1, gen.calls)
	auditlogtest.OnlyWriteFailed(t, gen.records, "authn.login.oauth", "alice", http.StatusInternalServerError)
}

// A verified identity the name guard refuses is one denied record,
// conformant, naming the Secret it would have written, with the guard's
// reason and no status code: authn refused before asking the apiserver
// (AUDIT-4).
func TestLoginRefusalIsRecorded(t *testing.T) {
	gen := &fakeGenerator{
		err: kubeconfig.Refused(kubeconfig.RefusalClaimed,
			status.Refused(status.CauseUsernameUnavailable, errors.New("the username isn't available to this identity"))),
		written: storage.Written{Namespace: "krateo-system", Name: storage.ClientConfigSecretName("alice"), Verb: "create"},
	}
	rec, _ := oauthLoginWith(t, `{"status":{"subject":"1001","name":"Alice","preferredUsername":"alice","groups":["devs"]}}`, true, gen)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Equal(t, 1, gen.calls)
	assert.NotContains(t, rec.Body.String(), "accessToken")
	r := auditlogtest.Only(t, gen.records)
	assert.Equal(t, "authn.login.oauth", auditlogtest.String(r, "krateo.action"))
	assert.Equal(t, audit.OutcomeDenied, auditlogtest.String(r, "krateo.audit.outcome"))
	assert.Equal(t, audit.DenialReasonNameClaimed, auditlogtest.String(r, "krateo.audit.denial_reason"))
	assert.Equal(t, storage.ClientConfigSecretName("alice"), auditlogtest.String(r, "krateo.audit.object_ref.name"))
	_, ok := auditlogtest.Int(r, "http.response.status_code")
	assert.False(t, ok, "authn refused before asking the apiserver")
}
