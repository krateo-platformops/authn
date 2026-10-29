package identitybackfill

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const ns = "krateo-system"

type fakeLookup struct {
	mappings map[string]bool
	basic    map[string]bool
	failFor  string
}

func (f fakeLookup) ServiceAccountMappingExists(_ context.Context, u string) (bool, error) {
	if u == f.failFor {
		return false, errors.New("apiserver unavailable")
	}
	return f.mappings[u], nil
}

func (f fakeLookup) BasicUserExists(_ context.Context, u string) (bool, error) {
	return f.basic[u], nil
}

// fakeAPIServer serves a Secret list for ns and records every update.
type fakeAPIServer struct {
	*httptest.Server
	mu      sync.Mutex
	updates map[string]map[string]string // secret name -> annotations written
}

func newFakeAPIServer(t *testing.T, items []corev1.Secret) *fakeAPIServer {
	t.Helper()
	f := &fakeAPIServer{updates: map[string]map[string]string{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		base := "/api/v1/namespaces/" + ns + "/secrets"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			_ = json.NewEncoder(w).Encode(&corev1.SecretList{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "SecretList"},
				Items:    items,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, base+"/"):
			body, _ := io.ReadAll(r.Body)
			sec := corev1.Secret{}
			require.NoError(t, json.Unmarshal(body, &sec))
			f.mu.Lock()
			f.updates[sec.Name] = sec.Annotations
			f.mu.Unlock()
			_, _ = w.Write(body)
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func TestRun(t *testing.T) {
	items := []corev1.Secret{
		clientConfig(t, "authn-clientconfig", cert(t, "authn", []string{"authn"}), nil),
		clientConfig(t, "cdc-clientconfig", cert(t, "cdc", []string{"krateo:services"}), nil),
		clientConfig(t, "bob-clientconfig", cert(t, "bob", []string{"devs"}), nil),
		clientConfig(t, "admin-clientconfig", cert(t, "admin", []string{"admins", "Sales, EMEA"}), nil),
		clientConfig(t, "both-clientconfig", cert(t, "both", nil), nil),
		// Already stamped by a login: must not be touched.
		clientConfig(t, "carol-clientconfig", cert(t, "carol", []string{"devs"}), map[string]string{
			storage.StrategyAnnotation: "oidc",
			storage.GroupsAnnotation:   "devs",
		}),
		// Half stamped: only the missing key is added, the existing one kept.
		clientConfig(t, "dave-clientconfig", cert(t, "dave", []string{"ops"}), map[string]string{
			storage.StrategyAnnotation: "ldap",
		}),
		// Unreadable certificate: skipped, never stamped with a guess.
		clientConfig(t, "broken-clientconfig", "garbage", nil),
		// Lookup error: skipped, retried next start.
		clientConfig(t, "flaky-clientconfig", cert(t, "flaky", nil), nil),
		// Not a clientconfig: ignored.
		{ObjectMeta: metav1.ObjectMeta{Name: "authn-jwt-signing-key", Namespace: ns}},
	}
	api := newFakeAPIServer(t, items)

	res, err := Run(context.Background(), Options{
		RestConfig:   &rest.Config{Host: api.URL},
		Namespaces:   []string{ns, ns, ""}, // duplicates and empties are ignored
		SelfUsername: "authn",
		Lookup: fakeLookup{
			mappings: map[string]bool{"cdc": true, "both": true},
			basic:    map[string]bool{"bob": true, "both": true},
			failFor:  "flaky",
		},
		Log: zerolog.Nop(),
	})
	require.NoError(t, err)

	assert.Equal(t, Result{Scanned: 9, Stamped: 6, Skipped: 2}, res)

	want := map[string]map[string]string{
		"authn-clientconfig": {storage.StrategyAnnotation: "self", storage.GroupsAnnotation: "authn"},
		"cdc-clientconfig":   {storage.StrategyAnnotation: "serviceaccount", storage.GroupsAnnotation: "krateo:services"},
		"bob-clientconfig":   {storage.StrategyAnnotation: "basic", storage.GroupsAnnotation: "devs"},
		"admin-clientconfig": {storage.StrategyAnnotation: "unknown", storage.GroupsAnnotation: "admins\nSales, EMEA"},
		"both-clientconfig":  {storage.StrategyAnnotation: "unknown", storage.GroupsAnnotation: ""},
		"dave-clientconfig":  {storage.StrategyAnnotation: "ldap", storage.GroupsAnnotation: "ops"},
	}
	for name, ann := range want {
		got, ok := api.updates[name]
		if assert.True(t, ok, "%s must be stamped", name) {
			for k, v := range ann {
				assert.Equal(t, v, got[k], "%s %s", name, k)
			}
			assert.Equal(t, "keep", got["unrelated"], "%s: unrelated annotations are preserved", name)
		}
	}
	for _, name := range []string{"carol-clientconfig", "broken-clientconfig", "flaky-clientconfig", "authn-jwt-signing-key"} {
		assert.NotContains(t, api.updates, name, "%s must not be written", name)
	}
}

func clientConfig(t *testing.T, name, certData string, annotations map[string]string) corev1.Secret {
	t.Helper()
	ann := map[string]string{"unrelated": "keep"}
	for k, v := range annotations {
		ann[k] = v
	}
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: ann, ResourceVersion: "1"},
		Data:       map[string][]byte{storage.ClientCertLabel: []byte(certData)},
	}
}

// cert mints a self-signed client certificate for cn with groups as its O=,
// base64-PEM encoded as a clientconfig Secret stores it.
func cert(t *testing.T, cn string, groups []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: groups},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
