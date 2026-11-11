package auditlog

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The CSR create, approve and delete are steps of one issuance, not records of
// their own (#119's scope). What keeps a failed step from being silent is the
// login's own record: a CSR the apiserver refuses fails Generate, and the
// login records a failure naming the Secret it would have written, with the
// verb it would have sent. Driven through the real generator.
func TestACSRFailureIsTheLoginsFailureRecord(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	var csrCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/krateo-system/secrets/alice-clientconfig":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
		case r.URL.Path == "/apis/certificates.k8s.io/v1/certificatesigningrequests":
			csrCalls++
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`))
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	gen := config.NewGenerator(&rest.Config{Host: srv.URL},
		config.CAData("Y2E="), config.KubernetesURL("https://k8s.example"))
	user := &userinfo.DefaultUser{Name: "alice", ID: "1", Groups: []string{"devs"},
		Subject: userinfo.Subject{Issuer: "krateo-system", ID: "alice"}}

	issued, err := gen.Generate(storage.StrategyBasic, user)
	require.Error(t, err, "a refused CSR fails the issuance")
	require.Equal(t, 1, csrCalls)
	assert.Equal(t, storage.Written{Namespace: "krateo-system", Name: "alice-clientconfig", Verb: "create"}, issued.Secret,
		"the Secret the login would have written, nothing stored")
	assert.Empty(t, config.RefusalOf(err), "a failure, not a refusal")

	r, rec := newRecorder(t)
	r.Issuance(get("/basic/login"), LoginAction(storage.StrategyBasic), user, jwtutil.PrincipalHuman, issued, err)
	got := rec.Only(t)
	audittest.AssertConformant(t, audit.WriterRequest, got)
	audittest.AssertRequiredKeysDetected(t, audit.WriterRequest, got)
	attrs := audittest.Attributes(got)
	v, _ := attr(t, attrs, "krateo.audit.outcome")
	assert.Equal(t, audit.OutcomeFailure, v.AsString())
	v, _ = attr(t, attrs, "krateo.audit.object_ref.name")
	assert.Equal(t, "alice-clientconfig", v.AsString())
	_, hasStatus := attr(t, attrs, "http.response.status_code")
	assert.False(t, hasStatus, "no request was sent for the Secret, so no authority answered for it")
}
