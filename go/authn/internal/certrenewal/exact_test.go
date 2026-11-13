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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

var exactNaming = storage.Naming{Exact: true}

func certOf(t *testing.T, cn string, groups []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, Organization: groups},
		NotBefore: now, NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// secretsServer serves Secrets by name in krateo-system and records every
// request; anything else (a CSR above all) is an error.
func secretsServer(t *testing.T, secrets map[string]*corev1.Secret) (*rest.Config, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		const base = "/api/v1/namespaces/krateo-system/secrets/"
		if !strings.HasPrefix(r.URL.Path, base) {
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, base)
		switch r.Method {
		case http.MethodGet:
			if sec, ok := secrets[name]; ok {
				_ = json.NewEncoder(w).Encode(sec)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(body)
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}, &calls
}

func secretOf(name, certData string, annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "krateo-system", Annotations: annotations},
		Data:       map[string][]byte{storage.ClientCertLabel: []byte(certData)}}
}

// The X/Y pair at the renewer. authn's username here is john.doe, whose
// legacy name, where signup writes, holds johndoe's credential. With exact
// naming that Secret is never used as authn's, and never replaced: the
// renewal fails before any CSR, and is recorded as a failure. With legacy
// naming it is read as authn's, as main does.
func TestRenewerXYNeverUsesOrReplacesAnotherUsersSecret(t *testing.T) {
	johndoe := secretOf("johndoe-clientconfig", certOf(t, "johndoe", []string{"devs"}), nil)
	rc, calls := secretsServer(t, map[string]*corev1.Secret{"johndoe-clientconfig": johndoe})
	ctl, records := auditlogtest.NewController(t, "system:serviceaccount:krateo-system:authn")
	logs, l := logtest.Capture()
	r, err := New(Options{RestConfig: rc, Namespace: "krateo-system", Username: "john.doe", Log: l, Audit: ctl, Naming: exactNaming})
	require.NoError(t, err)

	crt, sec, err := r.current(context.Background())
	require.NoError(t, err)
	assert.Nil(t, crt, "johndoe's certificate is never authn's")
	assert.Nil(t, sec)

	wait, err := r.Ensure(context.Background())
	require.ErrorIs(t, err, errHeldByAnother)
	assert.Equal(t, retryInterval, wait)
	for _, c := range *calls {
		assert.True(t, strings.HasPrefix(c, "GET "), "nothing but reads: %s", c)
	}
	rec := records.Only(t)
	audittest.AssertConformant(t, audit.WriterController, rec)
	assert.Equal(t, "failure", auditlogtest.String(rec, "krateo.audit.outcome"))
	assert.Equal(t, "johndoe-clientconfig", auditlogtest.String(rec, "krateo.audit.object_ref.name"))
	logtest.NoIdentityIfAny(t, logs)

	// Legacy naming reads it, as main does.
	r, err = New(Options{RestConfig: rc, Namespace: "krateo-system", Username: "john.doe", Log: zerolog.Nop()})
	require.NoError(t, err)
	crt, _, err = r.current(context.Background())
	require.NoError(t, err)
	require.NotNil(t, crt)
	assert.Equal(t, "johndoe", crt.Subject.CommonName)
}

// With exact naming, authn's own Secret is read exact name first and, owned,
// used: its own legacy Secret (CN = its username) too.
func TestRenewerReadsItsOwnSecretUnderEitherName(t *testing.T) {
	for _, name := range []string{"john.doe-clientconfig", "johndoe-clientconfig"} {
		rc, calls := secretsServer(t, map[string]*corev1.Secret{name: secretOf(name, certOf(t, "john.doe", nil), nil)})
		r, err := New(Options{RestConfig: rc, Namespace: "krateo-system", Username: "john.doe", Log: zerolog.Nop(), Naming: exactNaming})
		require.NoError(t, err)
		crt, sec, err := r.current(context.Background())
		require.NoError(t, err)
		require.NotNil(t, crt, name)
		assert.Equal(t, name, sec.Name)
		assert.Equal(t, "GET /api/v1/namespaces/krateo-system/secrets/john.doe-clientconfig", (*calls)[0], "exact first")
	}
}

// With exact naming, syncAnnotations also stamps the username annotation and
// the labels (principal service), and a change to a label is recorded; with
// legacy naming, a label alone is nothing to write.
func TestSyncAnnotationsStampsTheIdentityKeys(t *testing.T) {
	cert := certOf(t, "authn", []string{"authn"})
	current := storage.CertValidityAnnotations(cert)
	identity, err := storage.IdentityAnnotations(storage.StrategySelf, cert)
	require.NoError(t, err)
	for k, v := range identity {
		current[k] = v
	}
	current[storage.UsernameAnnotation] = "authn"
	full := map[string]string{storage.PrincipalLabel: "service", storage.UsernameLabelLabel: "authn"}

	for _, tc := range []struct {
		name          string
		naming        storage.Naming
		labels        map[string]string
		write, record bool
	}{
		{"exact: complete", exactNaming, full, false, false},
		{"exact: labels missing", exactNaming, nil, true, true},
		{"exact: a wrong principal", exactNaming, map[string]string{storage.PrincipalLabel: "human", storage.UsernameLabelLabel: "authn"}, true, true},
		{"legacy: labels missing is nothing to write", storage.Naming{}, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var written []corev1.Secret
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body, _ := io.ReadAll(r.Body)
				var s corev1.Secret
				_ = json.Unmarshal(body, &s)
				written = append(written, s)
				_, _ = w.Write(body)
			}))
			t.Cleanup(srv.Close)
			ctl, records := auditlogtest.NewController(t, "system:serviceaccount:krateo-system:authn")
			r, err := New(Options{RestConfig: &rest.Config{Host: srv.URL}, Namespace: "krateo-system",
				Username: "authn", Log: zerolog.Nop(), Audit: ctl, Naming: tc.naming})
			require.NoError(t, err)
			sec := secretOf("authn-clientconfig", cert, current)
			sec.Labels = tc.labels
			r.syncAnnotations(context.Background(), sec)
			if !tc.write {
				assert.Empty(t, written)
				assert.Empty(t, records.Records())
				return
			}
			require.Len(t, written, 1)
			assert.Equal(t, full, written[0].Labels)
			assert.Equal(t, "authn", written[0].Annotations[storage.UsernameAnnotation])
			assert.Equal(t, tc.record, len(records.Records()) == 1)
		})
	}
}
