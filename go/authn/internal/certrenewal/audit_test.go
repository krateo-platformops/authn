package certrenewal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// A renewal that fails before the Secret write (the CSR is refused) is one
// failure record naming authn's clientconfig Secret, with the write it would
// have sent, read from whether the Secret exists, and no status code. When the
// Secret can't be read, the verb is omitted and marked, never guessed. Driven
// through the renewer, so dropping the call or fixing its verb fails here.
func TestARenewalThatFailsBeforeTheWriteIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secretCode int
		wantVerb   string
	}{
		{"no Secret yet: create", http.StatusNotFound, "create"},
		{"Secret exists: update", http.StatusOK, "update"},
		{"Secret unreadable: no verb", http.StatusInternalServerError, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/apis/certificates.k8s.io/v1/certificatesigningrequests":
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`)
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/krateo-system/secrets/authn-clientconfig":
					w.WriteHeader(tc.secretCode)
					if tc.secretCode == http.StatusOK {
						_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"authn-clientconfig","namespace":"krateo-system"}}`)
						return
					}
					_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":`+map[int]string{404: "404", 500: "500"}[tc.secretCode]+`}`)
				default:
					t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			ctl, records := auditlogtest.NewController(t, "system:serviceaccount:krateo-system:authn")
			r, err := New(Options{RestConfig: &rest.Config{Host: srv.URL}, Namespace: "krateo-system",
				CAData: "Y2E=", ServerURL: "https://k8s.example", Username: "authn", Log: zerolog.Nop(), Audit: ctl})
			require.NoError(t, err)
			_, err = r.issue(context.Background(), "test")
			require.Error(t, err, "the refused CSR fails the renewal")

			rec := records.Only(t)
			var opts []audittest.Option
			if tc.wantVerb == "" {
				opts = append(opts, audittest.AllowIncomplete(audit.KeyVerb))
			}
			audittest.AssertConformant(t, audit.WriterController, rec, opts...)
			assert.Equal(t, "failure", auditlogtest.String(rec, "krateo.audit.outcome"))
			assert.Equal(t, "authn-clientconfig", auditlogtest.String(rec, "krateo.audit.object_ref.name"))
			assert.Equal(t, tc.wantVerb, auditlogtest.String(rec, audit.KeyVerb))
			for _, kv := range audittest.Attributes(rec) {
				assert.NotEqual(t, "http.response.status_code", string(kv.Key), "no request was sent for the Secret")
			}
		})
	}
}
