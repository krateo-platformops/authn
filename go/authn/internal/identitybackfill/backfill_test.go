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
	"fmt"
	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

const ns = "krateo-system"

type fakeLookup struct {
	mappings map[string]bool
	basic    map[string]bool
	failFor  string
}

func (f fakeLookup) ServiceAccountMapping(_ context.Context, u string) (*sav1alpha1.ServiceAccount, error) {
	if u == f.failFor {
		return nil, errors.New("apiserver unavailable")
	}
	if !f.mappings[u] {
		return nil, nil
	}
	return &sav1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: u, Namespace: ns, UID: types.UID("uid-" + u)}}, nil
}

func (f fakeLookup) BasicUserExists(_ context.Context, u string) (bool, error) {
	return f.basic[u], nil
}

// fakeAPIServer serves a Secret list for ns and records every update.
type fakeAPIServer struct {
	*httptest.Server
	mu      sync.Mutex
	updates map[string]map[string]string // secret name -> annotations written
	owners  map[string][]metav1.OwnerReference
	// refuse answers the PUT of these Secrets with that HTTP status, as the
	// apiserver does for a conflict or a forbidden write.
	refuse map[string]int
}

func newFakeAPIServer(t *testing.T, items []corev1.Secret) *fakeAPIServer {
	t.Helper()
	f := &fakeAPIServer{updates: map[string]map[string]string{}, owners: map[string][]metav1.OwnerReference{}}
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
			if code := f.refuse[sec.Name]; code != 0 {
				w.WriteHeader(code)
				// As the apiserver does, the message names the Secret.
				_, _ = fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":%d,"message":"secrets \"%s\" is refused"}`, code, sec.Name)
				return
			}
			f.mu.Lock()
			f.updates[sec.Name] = sec.Annotations
			f.owners[sec.Name] = sec.OwnerReferences
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
	ctl, records := auditlogtest.NewController(t, "system:serviceaccount:"+ns+":authn")

	res, err := Run(context.Background(), Options{
		RestConfig:   &rest.Config{Host: api.URL},
		Namespaces:   []string{ns, ns, ""}, // duplicates and empties are ignored
		SelfUsername: "authn",
		Lookup: fakeLookup{
			mappings: map[string]bool{"cdc": true, "both": true},
			basic:    map[string]bool{"bob": true, "both": true},
			failFor:  "flaky",
		},
		Log:   zerolog.Nop(),
		Audit: ctl,
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

	// Every write stamps an authorization-bearing annotation, so each one is a
	// conformant controller record of that Secret, and nothing else is (AUDIT-4).
	recs := records.Records()
	require.Len(t, recs, len(want), "one record per write")
	for _, r := range recs {
		audittest.AssertConformant(t, audit.WriterController, r)
		audittest.AssertRequiredKeysDetected(t, audit.WriterController, r)
		assert.Equal(t, "authn.identity.backfilled", auditlogtest.String(r, "krateo.action"))
		assert.Equal(t, "update", auditlogtest.String(r, "krateo.audit.verb"))
		assert.Contains(t, want, auditlogtest.String(r, "krateo.audit.object_ref.name"))
	}
	for name, owners := range api.owners {
		assert.Empty(t, owners, "%s: no owner without a MappingNamespace", name)
	}
}

// In the mappings' namespace, a service identity's Secret with no owner gets
// its mapping as owner, by UID, in the same write as any missing annotation.
// One that already has an owner, or isn't a service identity's, is not given
// one. One whose mapping is gone is counted as an orphan and never written,
// let alone deleted.
func TestRunOwners(t *testing.T) {
	svc := map[string]string{storage.StrategyAnnotation: "serviceaccount", storage.GroupsAnnotation: "krateo:cdc"}
	owned := clientConfig(t, "svc-owned-clientconfig", cert(t, "svc-owned", []string{"krateo:cdc"}), svc)
	owned.OwnerReferences = []metav1.OwnerReference{{APIVersion: "serviceaccount.authn.krateo.io/v1alpha1", Kind: "ServiceAccount", Name: "svc-owned", UID: "uid-older"}}
	items := []corev1.Secret{
		clientConfig(t, "svc-new-clientconfig", cert(t, "svc-new", []string{"krateo:cdc"}), nil),
		clientConfig(t, "svc-stamped-clientconfig", cert(t, "svc-stamped", []string{"krateo:cdc"}), svc),
		owned,
		clientConfig(t, "svc-gone-clientconfig", cert(t, "svc-gone", []string{"krateo:cdc"}), svc),
		clientConfig(t, "bob-clientconfig", cert(t, "bob", []string{"devs"}), nil),
	}
	lookup := fakeLookup{
		mappings: map[string]bool{"svc-new": true, "svc-stamped": true, "svc-owned": true},
		basic:    map[string]bool{"bob": true},
	}

	api := newFakeAPIServer(t, items)
	res, err := Run(context.Background(), Options{
		RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns},
		MappingNamespace: ns, SelfUsername: "authn", Lookup: lookup, Log: zerolog.Nop(),
	})
	require.NoError(t, err)
	assert.Equal(t, Result{Scanned: 5, Stamped: 2, Owned: 2, Orphaned: 1}, res)

	for _, name := range []string{"svc-new", "svc-stamped"} {
		assert.Equal(t, []metav1.OwnerReference{{
			APIVersion: "serviceaccount.authn.krateo.io/v1alpha1", Kind: "ServiceAccount",
			Name: name, UID: types.UID("uid-" + name),
		}}, api.owners[name+"-clientconfig"], name)
	}
	assert.Equal(t, "serviceaccount", api.updates["svc-new-clientconfig"][storage.StrategyAnnotation],
		"the owner and the missing annotations go in one write")
	assert.Empty(t, api.owners["bob-clientconfig"], "a person's credential gets no owner")
	assert.NotContains(t, api.updates, "svc-owned-clientconfig", "an existing owner is never replaced")
	assert.NotContains(t, api.updates, "svc-gone-clientconfig", "an orphan is reported, never written")

	// Outside the mappings' namespace no owner is added: an ownerReference
	// can't cross namespaces.
	api = newFakeAPIServer(t, items)
	res, err = Run(context.Background(), Options{
		RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns},
		MappingNamespace: "elsewhere", SelfUsername: "authn", Lookup: lookup, Log: zerolog.Nop(),
	})
	require.NoError(t, err)
	assert.Zero(t, res.Owned)
	assert.Zero(t, res.Orphaned)
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

// A write the apiserver refuses is a failure record with the apiserver's
// status, never a success: the annotation that policy decides from wasn't
// stamped (authn#127, N17).
func TestRunRecordsARefusedWriteAsAFailure(t *testing.T) {
	for _, code := range []int{http.StatusConflict, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			api := newFakeAPIServer(t, []corev1.Secret{
				clientConfig(t, "bob-clientconfig", cert(t, "bob", []string{"devs"}), nil),
			})
			api.refuse = map[string]int{"bob-clientconfig": code}
			ctl, records := auditlogtest.NewController(t, "system:serviceaccount:"+ns+":authn")
			res, err := Run(context.Background(), Options{
				RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
				Lookup: fakeLookup{basic: map[string]bool{"bob": true}}, Log: zerolog.Nop(), Audit: ctl,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, res.Skipped)
			r := records.Only(t)
			audittest.AssertConformant(t, audit.WriterController, r)
			assert.Equal(t, "failure", auditlogtest.String(r, "krateo.audit.outcome"))
			for _, kv := range audittest.Attributes(r) {
				if kv.Key == "http.response.status_code" {
					assert.Equal(t, int64(code), kv.Value.AsInt64())
				}
			}
		})
	}
}
