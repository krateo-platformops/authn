package delegate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/configtest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/plumbing/endpoints"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// secretsAPI is an apiserver holding Secrets in krateo-system: create,
// read and replace, as the credential store sends them.
type secretsAPI struct {
	mu     sync.Mutex
	stored map[string]corev1.Secret
}

func newSecretsAPI(t *testing.T) (*secretsAPI, *rest.Config) {
	t.Helper()
	a := &secretsAPI{stored: map[string]corev1.Secret{}}
	const base = "/api/v1/namespaces/krateo-system/secrets"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		a.mu.Lock()
		defer a.mu.Unlock()
		name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, base), "/")
		var sec corev1.Secret
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(body, &sec))
			name = sec.Name
		}
		have, exists := a.stored[name]
		switch {
		case r.Method == http.MethodGet && exists:
			_ = json.NewEncoder(w).Encode(have)
		case r.Method == http.MethodPost && exists:
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"AlreadyExists","code":409}`)
		case r.Method == http.MethodPost, r.Method == http.MethodPut && exists:
			sec.ResourceVersion = have.ResourceVersion + "1"
			a.stored[name] = sec
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			}
			_ = json.NewEncoder(w).Encode(sec)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
		}
	}))
	t.Cleanup(srv.Close)
	return a, &rest.Config{Host: srv.URL}
}

// read is the Secret named name as a reader gets it back: what was sent as
// StringData is Data.
func (a *secretsAPI) read(name string) (*corev1.Secret, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sec, ok := a.stored[name]
	if !ok {
		return nil, false
	}
	out := sec.DeepCopy()
	if out.Data == nil {
		out.Data = map[string][]byte{}
	}
	for k, v := range sec.StringData {
		out.Data[k] = []byte(v)
	}
	out.StringData = nil
	return out, true
}

// authn#167 in one test, with the real generator, signer and store under the
// route: the token /delegate answers and the Secret it stored agree, by the
// very check snowplow serves the Secret by. alice's step-up group is in
// neither, and a second exchange through the same actor with other groups
// replaces the credential, which the first token then no longer matches.
func TestTheIssuedTokenIsTheStoredCredentials(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	api, storeRC := newSecretsAPI(t)
	signer, _ := configtest.FakeSigner(t)
	gen := kubeconfig.NewGenerator(storeRC, kubeconfig.CAData("ca"), kubeconfig.KubernetesURL("https://k8s.example"),
		kubeconfig.Log(zerolog.Nop()), kubeconfig.Lookup(everyoneSignedIn{}),
		kubeconfig.Storage(storage.Default(storeRC)), kubeconfig.CSRClient(signer))
	h, _ := k.withGenerator(t, rc, everyoneSignedIn{}, gen)

	out, nfo := issued(t, k, exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil))))
	require.NotNil(t, nfo.Act)
	assert.Equal(t, []string{"devs"}, nfo.Groups)
	sec, ok := api.read(endpoints.DelegatedSecretName(nfo.Username, nfo.Act.Sub))
	require.True(t, ok, "the credential is stored under the token's person and actor")
	assert.Equal(t, endpoints.DelegatedCredentialHeld,
		endpoints.CheckDelegatedCredential(sec, nfo.Username, nfo.Act.Sub, nfo.Groups, time.Now()))
	assert.Equal(t, endpoints.DelegatedCredentialHeld,
		endpoints.CheckDelegatedCredential(sec, nfo.Username, nfo.Act.Sub, nfo.Groups, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second-time.Second)),
		"held for as long as the token lives")
	assert.Len(t, api.stored, 1, "only the delegated Secret is written")

	// A second exchange, with groups that differ, replaces it.
	other := tokenWithGroups(t, k, []string{"devs", "ops"})
	_, second := issued(t, k, exchange(h, "projected-sa-token", form(other)))
	sec, _ = api.read(endpoints.DelegatedSecretName(second.Username, second.Act.Sub))
	assert.Equal(t, endpoints.DelegatedCredentialHeld,
		endpoints.CheckDelegatedCredential(sec, second.Username, second.Act.Sub, second.Groups, time.Now()))
	assert.Equal(t, endpoints.DelegatedCredentialMismatch,
		endpoints.CheckDelegatedCredential(sec, nfo.Username, nfo.Act.Sub, nfo.Groups, time.Now()),
		"the first token's groups are no longer the credential's")
}

// tokenWithGroups is alice's authn token with groups.
func tokenWithGroups(t *testing.T, k keys, groups []string) string {
	t.Helper()
	tok, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
		Username: "alice", Groups: groups, Duration: time.Hour,
		KeyID: "current", PrivateKey: k.current, Principal: jwtutil.PrincipalHuman,
	})
	require.NoError(t, err)
	return tok
}
