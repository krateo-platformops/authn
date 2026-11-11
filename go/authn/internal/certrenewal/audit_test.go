package certrenewal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
				case r.Method == http.MethodGet && r.URL.Path == "/apis/certificates.k8s.io/v1/certificatesigningrequests/authn":
					// After a failed create, signup (plumbing v1.51.0) reads the CSR to
					// clean up one the apiserver stored anyway; a refused create stored
					// nothing.
					w.WriteHeader(http.StatusNotFound)
					_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
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

func authnCert(t *testing.T, groups []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "authn", Organization: groups},
		NotBefore: now, NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// syncAnnotations writes whenever an annotation is stale, but an audit record
// is owed only when an authorization-bearing one (strategy, groups) changes:
// the validity window alone is observability (AUDIT-4, authorization-bearing
// annotations ruling).
func TestSyncAnnotationsRecordsOnlyAuthorizationChanges(t *testing.T) {
	cert := authnCert(t, []string{"authn"})
	identity, err := storage.IdentityAnnotations(storage.StrategySelf, cert)
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		have   map[string]string
		record bool
	}{
		{"only the validity window is stale: written, not recorded", identity, false},
		{"the groups are stale: written and recorded", map[string]string{storage.StrategyAnnotation: "self", storage.GroupsAnnotation: "old"}, true},
		{"the strategy is missing: written and recorded", map[string]string{storage.GroupsAnnotation: identity[storage.GroupsAnnotation]}, true},
		{"the groups are stale and the write is refused: a failure", map[string]string{storage.StrategyAnnotation: "self", storage.GroupsAnnotation: "old"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var puts int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodPut {
					t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
					return
				}
				puts++
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(tc.name, "refused") {
					w.WriteHeader(http.StatusConflict)
					_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":409}`)
					return
				}
				_, _ = w.Write(body)
			}))
			t.Cleanup(srv.Close)
			ctl, records := auditlogtest.NewController(t, "system:serviceaccount:krateo-system:authn")
			r, err := New(Options{RestConfig: &rest.Config{Host: srv.URL}, Namespace: "krateo-system",
				Username: "authn", Log: zerolog.Nop(), Audit: ctl})
			require.NoError(t, err)
			sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "authn-clientconfig", Namespace: "krateo-system",
				Annotations: tc.have}, Data: map[string][]byte{storage.ClientCertLabel: []byte(cert)}}
			r.syncAnnotations(context.Background(), sec)
			require.Equal(t, 1, puts, "a stale annotation is written")
			if !tc.record {
				assert.Empty(t, records.Records())
				return
			}
			rec := records.Only(t)
			audittest.AssertConformant(t, audit.WriterController, rec)
			assert.Equal(t, "authn.servicecert.annotated", auditlogtest.String(rec, "krateo.action"))
			assert.Equal(t, "update", auditlogtest.String(rec, audit.KeyVerb))
			want := "success"
			if strings.Contains(tc.name, "refused") {
				want = "failure" // authn#127, N17: a refused write is never a success
			}
			assert.Equal(t, want, auditlogtest.String(rec, "krateo.audit.outcome"))
		})
	}
}
