package storage

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// putRecorder is an apiserver that answers a Secret create with 409 when
// exists is set, and records every Secret body it receives.
type putRecorder struct {
	mu      sync.Mutex
	exists  bool
	written []corev1.Secret
}

func (p *putRecorder) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		sec := corev1.Secret{}
		require.NoError(t, json.Unmarshal(body, &sec))
		p.mu.Lock()
		p.written = append(p.written, sec)
		exists := p.exists
		p.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && exists:
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"AlreadyExists","code":409}`))
		case r.Method == http.MethodPost, r.Method == http.MethodPut:
			_, _ = w.Write(body)
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A credential stored with an owner carries it as its only ownerReference, on
// create and on the update of an existing Secret alike, so the garbage
// collector deletes the Secret with its owner. Without an owner, none is set.
func TestPutWritesTheOwner(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	owner := metav1.OwnerReference{
		APIVersion: "serviceaccount.authn.krateo.io/v1alpha1",
		Kind:       "ServiceAccount",
		Name:       "cdc-krateo-system-fireworksapps-v1-0-0",
		UID:        "0b1f6c1e-2d6a-4b8e-9c3f-5a7e8d9f0a1b",
	}

	for _, exists := range []bool{false, true} {
		rec := &putRecorder{exists: exists}
		store := Default(&rest.Config{Host: rec.serve(t).URL})
		require.NoError(t, store.Put("cdc-krateo-system-fireworksapps-v1-0-0", &AuthInfo{Strategy: StrategyServiceAccount, Owner: &owner,
			CertData: identityCert(t, "cdc-krateo-system-fireworksapps-v1-0-0", []string{"krateo:cdc:fireworksapps-v1-0-0"})}))

		require.NotEmpty(t, rec.written)
		for _, sec := range rec.written {
			assert.Equal(t, []metav1.OwnerReference{owner}, sec.OwnerReferences, "exists=%v", exists)
		}
		if exists {
			assert.Len(t, rec.written, 2, "a create refused as AlreadyExists is retried as an update")
		}
	}

	rec := &putRecorder{}
	store := Default(&rest.Config{Host: rec.serve(t).URL})
	require.NoError(t, store.Put("alice", &AuthInfo{Strategy: StrategyBasic, CertData: identityCert(t, "alice", []string{"devs"})}))
	require.Len(t, rec.written, 1)
	assert.Empty(t, rec.written[0].OwnerReferences, "a person's credential has no owner")
}
