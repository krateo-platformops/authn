package serviceaccount

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// fakeGenerator stands in for the kubeconfig generator: it records that the
// identity's clientconfig was minted and returns a kubeconfig carrying a
// private key, as the real one does.
type fakeGenerator struct{ calls []string }

func (g *fakeGenerator) Generate(user userinfo.Info) ([]byte, time.Time, error) {
	g.calls = append(g.calls, user.GetUserName())
	return []byte(`{"kind":"Config","users":[{"name":"x","user":{"client-key-data":"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"}}]}`), time.Now().Add(time.Hour), nil
}

// fakeAPIServer answers the two calls the handler makes: the TokenReview and
// the list of ServiceAccount mappings in the operator namespace.
func fakeAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			_, _ = w.Write([]byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
				"status":{"authenticated":true,"audiences":["authn"],
				"user":{"username":"system:serviceaccount:krateo-system:cdc"}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			_, _ = w.Write([]byte(`{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList",
				"items":[{"metadata":{"name":"cdc-identity","namespace":"krateo-system"},
				"spec":{"serviceAccountRef":{"namespace":"krateo-system","name":"cdc"},"groups":["krateo:cdc"]}}]}`))
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

// The serviceaccount login must still mint the identity's clientconfig, but its
// response must not carry that kubeconfig: it holds a private key, and no
// service caller reads it (#36).
func TestHandlerOmitsKubeconfigFromResponse(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := fakeAPIServer(t)
	defer srv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	gen := &fakeGenerator{}
	route := Login(&rest.Config{Host: srv.URL}, LoginOptions{
		KubeconfigGenerator: gen,
		JwtDuration:         time.Hour,
		JwtPrivateKey:       key,
		JwtKeyID:            "test-key",
	})

	req := httptest.NewRequest(http.MethodPost, Path, nil)
	req.Header.Set("Authorization", "Bearer projected-sa-token")
	rec := httptest.NewRecorder()
	route.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"cdc-identity"}, gen.calls, "the clientconfig Secret must still be minted")

	var out map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.NotContains(t, out, "data", "the kubeconfig must not be in the response")
	assert.NotContains(t, rec.Body.String(), "client-key-data")
	assert.Contains(t, out, "accessToken")
	assert.Contains(t, out, "user")
	assert.True(t, strings.Contains(string(out["groups"]), "krateo:cdc"))
}
