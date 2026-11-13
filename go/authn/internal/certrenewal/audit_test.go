package certrenewal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
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
				case r.Method == http.MethodGet && signupCSR.MatchString(r.URL.Path):
					// After a failed create, signup (plumbing) reads the CSR to
					// clean up one the apiserver stored anyway; a refused create stored
					// nothing. Signup names its CSR <username>-<10 hex> (plumbing
					// v1.66.0, plumbing#137).
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

// fakeSigner is an apiserver that does what a renewal needs, end to end: it
// stores the CSR plumbing's signup creates, signs it with a test CA once it is
// approved, serves the certificate, accepts the cleanup delete, and stores the
// clientconfig Secret. secretExists makes the Secret's create answer 409, so
// signup updates it instead.
type fakeSigner struct {
	t            *testing.T
	ca           *x509.Certificate
	caKey        *rsa.PrivateKey
	secretExists bool

	mu  sync.Mutex
	csr *certv1.CertificateSigningRequest
	// name is the name of the CSR signup created: its own, <username>-<10
	// hex> (plumbing v1.66.0), which every later request addresses.
	name string
}

func newFakeSigner(t *testing.T, secretExists bool) *fakeSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &fakeSigner{t: t, ca: ca, caKey: key, secretExists: secretExists}
}

// sign issues the certificate the CSR asks for: its subject and key, for 30m.
// It runs on the server's goroutine, so it returns an error rather than
// failing the test itself.
func (f *fakeSigner) sign(req []byte) ([]byte, error) {
	block, _ := pem.Decode(req)
	if block == nil {
		return nil, fmt.Errorf("spec.request is not a PEM CSR")
	}
	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: cr.Subject,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, f.ca, cr.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// status is an apiserver Status body.
func status(code int32, reason metav1.StatusReason) metav1.Status {
	st := metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: metav1.StatusFailure, Reason: reason, Code: code}
	if code < 300 {
		st.Status = metav1.StatusSuccess
	}
	return st
}

func (f *fakeSigner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const csrs = "/apis/certificates.k8s.io/v1/certificatesigningrequests"
	const secrets = "/api/v1/namespaces/krateo-system/secrets"
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	writeJSON := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	// fail reports a fake's own error. It runs on the server's goroutine, so
	// it marks the test failed (Errorf) and answers 500, never FailNow.
	fail := func(err error) {
		f.t.Errorf("fake apiserver: %s %s: %v", r.Method, r.URL.Path, err)
		writeJSON(http.StatusInternalServerError, status(http.StatusInternalServerError, metav1.StatusReasonInternalError))
	}
	// decode reads a request body as client-go sent it: protobuf for the typed
	// clientset (the CSR), JSON for plumbing's REST client (the Secret).
	decode := func(into runtime.Object) bool {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			_, _, err = scheme.Codecs.UniversalDeserializer().Decode(body, nil, into)
		}
		if err != nil {
			fail(err)
			return false
		}
		return true
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == csrs:
		var csr certv1.CertificateSigningRequest
		if !decode(&csr) {
			return
		}
		csr.UID = "uid-csr"
		f.csr, f.name = &csr, csr.Name
		writeJSON(http.StatusCreated, f.csr)
	case r.Method == http.MethodPut && f.name != "" && r.URL.Path == csrs+"/"+f.name+"/approval":
		if f.csr == nil {
			fail(fmt.Errorf("approval before create"))
			return
		}
		crt, err := f.sign(f.csr.Spec.Request)
		if err != nil {
			fail(err)
			return
		}
		f.csr.Status.Conditions = append(f.csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
			Type: certv1.CertificateApproved, Status: corev1.ConditionTrue})
		f.csr.Status.Certificate = crt
		writeJSON(http.StatusOK, f.csr)
	case r.Method == http.MethodGet && f.name != "" && r.URL.Path == csrs+"/"+f.name:
		if f.csr == nil {
			writeJSON(http.StatusNotFound, status(http.StatusNotFound, metav1.StatusReasonNotFound))
			return
		}
		writeJSON(http.StatusOK, f.csr)
	case r.Method == http.MethodDelete && f.name != "" && r.URL.Path == csrs+"/"+f.name:
		f.csr = nil
		writeJSON(http.StatusOK, status(http.StatusOK, ""))
	case r.Method == http.MethodPost && r.URL.Path == secrets:
		if f.secretExists {
			writeJSON(http.StatusConflict, status(http.StatusConflict, metav1.StatusReasonAlreadyExists))
			return
		}
		var sec corev1.Secret
		if !decode(&sec) {
			return
		}
		sec.UID, sec.ResourceVersion = "uid-sec", "1"
		writeJSON(http.StatusCreated, sec)
	case r.Method == http.MethodPut && r.URL.Path == secrets+"/authn-clientconfig":
		var sec corev1.Secret
		if !decode(&sec) {
			return
		}
		sec.UID, sec.ResourceVersion = "uid-sec", "2"
		writeJSON(http.StatusOK, sec)
	case r.Method == http.MethodGet && r.URL.Path == secrets+"/authn-clientconfig":
		// annotate's read-back, after the issue record is written.
		writeJSON(http.StatusOK, corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "authn-clientconfig",
			Namespace: "krateo-system", UID: "uid-sec", ResourceVersion: "2"}})
	default:
		f.t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// A renewal that succeeds is one success record for authn's clientconfig
// Secret, conformant for the controller writer, carrying the verb plumbing's
// signup sent and the apiserver's answer to it, and the stored uid. Driven
// through the renewer and plumbing's real signup against an apiserver that
// signs the CSR, so dropping the call, or recording a write signup didn't
// make, fails here. Both writes signup can send: a create, and the update
// after a create answered 409.
func TestARenewalThatStoresTheCertificateIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name         string
		secretExists bool
		verb         string
		code         int64
		rv           string
	}{
		{"no Secret yet: created", false, "create", http.StatusCreated, "1"},
		{"Secret exists: updated", true, "update", http.StatusOK, "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(newFakeSigner(t, tc.secretExists))
			t.Cleanup(srv.Close)

			ctl, records := auditlogtest.NewController(t, "system:serviceaccount:krateo-system:authn")
			r, err := New(Options{RestConfig: &rest.Config{Host: srv.URL}, Namespace: "krateo-system",
				CAData: "Y2E=", ServerURL: "https://k8s.example", Username: "authn", Groups: []string{"authn"},
				Log: zerolog.Nop(), Audit: ctl})
			require.NoError(t, err)
			_, err = r.issue(context.Background(), "test")
			require.NoError(t, err, "the signed CSR stores the certificate")

			var issued []sdklog.Record
			for _, rec := range records.Records() {
				if auditlogtest.String(rec, "krateo.action") == "authn.servicecert.issued" {
					issued = append(issued, rec)
				}
			}
			require.Len(t, issued, 1, "one record for the issue")
			rec := issued[0]
			audittest.AssertConformant(t, audit.WriterController, rec)
			audittest.AssertRequiredKeysDetected(t, audit.WriterController, rec)
			assert.Equal(t, "success", auditlogtest.String(rec, "krateo.audit.outcome"))
			assert.Equal(t, "authn-clientconfig", auditlogtest.String(rec, "krateo.audit.object_ref.name"))
			assert.Equal(t, "uid-sec", auditlogtest.String(rec, audit.KeyObjectUID))
			assert.Equal(t, tc.rv, auditlogtest.String(rec, audit.KeyObjectResourceVersion))
			assert.Equal(t, tc.verb, auditlogtest.String(rec, audit.KeyVerb))
			code := int64(0)
			for _, kv := range audittest.Attributes(rec) {
				if string(kv.Key) == "http.response.status_code" {
					code = kv.Value.AsInt64()
				}
			}
			assert.Equal(t, tc.code, code, "the apiserver's answer to the Secret's %s", tc.verb)
		})
	}
}

// signupCSR is the path of a CSR plumbing's signup creates for authn: named
// <username>-<10 hex>, its own (plumbing v1.66.0, plumbing#137).
var signupCSR = regexp.MustCompile(`^/apis/certificates\.k8s\.io/v1/certificatesigningrequests/authn-[0-9a-f]{10}$`)
