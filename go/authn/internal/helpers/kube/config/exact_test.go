package config

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// storeAPI is the apiserver the credential store writes to: Secrets by name
// in krateo-system, every write recorded.
type storeAPI struct {
	mu      sync.Mutex
	stored  map[string]*corev1.Secret
	written []string // "METHOD name"
}

func newStoreAPI(t *testing.T, secrets map[string]*corev1.Secret) (*storeAPI, *rest.Config) {
	t.Helper()
	a := &storeAPI{stored: map[string]*corev1.Secret{}}
	for k, v := range secrets {
		a.stored[k] = v.DeepCopy()
	}
	const base = "/api/v1/namespaces/krateo-system/secrets"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		a.mu.Lock()
		defer a.mu.Unlock()
		name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, base), "/")
		sec := &corev1.Secret{}
		if r.Method != http.MethodGet {
			body, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(body, sec))
			name = sec.Name
			a.written = append(a.written, r.Method+" "+name)
		}
		have, exists := a.stored[name]
		switch {
		case r.Method == http.MethodGet && exists:
			_ = json.NewEncoder(w).Encode(have)
		case r.Method == http.MethodPost && exists:
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, statusBody(409, "AlreadyExists", "exists"))
		case r.Method == http.MethodPost, r.Method == http.MethodPut && exists:
			a.stored[name] = sec
			_ = json.NewEncoder(w).Encode(sec)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, statusBody(404, "NotFound", "absent"))
		}
	}))
	t.Cleanup(srv.Close)
	return a, &rest.Config{Host: srv.URL}
}

// exactGenerator is a generator with exact naming, its default store writing
// to rc, the name guard reading secrets.
func exactGenerator(t *testing.T, rc *rest.Config, secrets map[string]*corev1.Secret) *kubeconfigGenerator {
	t.Helper()
	cli, _ := fakeSigner(t)
	gen := NewGenerator(rc, Naming(exact), CAData("ca"), KubernetesURL("https://k8s.example"), CertDuration(time.Hour),
		Log(zerolog.Nop()), Lookup(&namesLookup{secrets: secrets})).(*kubeconfigGenerator)
	gen.csrClient = cli
	return gen
}

// A sign-in with exact naming, end to end: john.doe, whose legacy Secret
// johndoe-clientconfig is its own and claimed by it, gets
// john.doe-clientconfig with the same claim, the username annotation and the
// labels; the legacy Secret is never written, nor deleted.
func TestExactSignInCarriesTheClaimAndLeavesTheLegacySecret(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := claims(storage.StrategyOIDC, "x")
	legacy := ownedBy(t, sharedY, userX, map[string]string{storage.ClaimAnnotation: mine})
	legacy.Namespace = "krateo-system"
	secrets := map[string]*corev1.Secret{sharedY: legacy}
	api, rc := newStoreAPI(t, secrets)

	issued, err := exactGenerator(t, rc, secrets).Generate(storage.StrategyOIDC, userAs(userX, "kc", "x"))
	require.NoError(t, err)
	assert.Equal(t, exactX, issued.Secret.Name)
	assert.Equal(t, []string{"POST " + exactX}, api.written, "the legacy Secret is never written")
	assert.Equal(t, legacy, api.stored[sharedY], "nor changed or deleted")

	got := api.stored[exactX]
	assert.Equal(t, mine, got.Annotations[storage.ClaimAnnotation], "the claim carried over")
	assert.Equal(t, userX, got.Annotations[storage.UsernameAnnotation])
	assert.Equal(t, map[string]string{storage.PrincipalLabel: "human", storage.UsernameLabelLabel: "john-doe--30f69670bba2"}, got.Labels)
}

// The X/Y pair through the writer: john.doe signing in next to johndoe's
// Secret writes its own exact Secret only.
func TestExactSignInXYWritesOnlyItsOwnName(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	y := ownedBy(t, sharedY, userY, map[string]string{storage.ClaimAnnotation: claims(storage.StrategyOIDC, "y")})
	secrets := map[string]*corev1.Secret{sharedY: y}
	api, rc := newStoreAPI(t, secrets)
	issued, err := exactGenerator(t, rc, secrets).Generate(storage.StrategyOIDC, userAs(userX, "kc", "x"))
	require.NoError(t, err)
	assert.Equal(t, exactX, issued.Secret.Name)
	assert.Equal(t, []string{"POST " + exactX}, api.written)
	assert.Equal(t, claims(storage.StrategyOIDC, "x"), api.stored[exactX].Annotations[storage.ClaimAnnotation], "its own claim, not johndoe's")
	assert.Equal(t, y, api.stored[sharedY])
}

// A step-up with exact naming writes <username>-clientconfig-stepup.
func TestExactStepUpName(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	api, rc := newStoreAPI(t, nil)
	issued, err := exactGenerator(t, rc, nil).GenerateStepUp(storage.StrategyOIDC,
		userinfo.NewStepUpUser(userAs(userX, "kc", "x"), 2), 15*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "john.doe-clientconfig-stepup", issued.Secret.Name)
	assert.Equal(t, []string{"POST john.doe-clientconfig-stepup"}, api.written)
}

// recordingStore records what the generator hands the store.
type recordingStore struct{ puts []storage.AuthInfo }

func (r *recordingStore) Put(name string, nfo *storage.AuthInfo) (storage.Written, error) {
	r.puts = append(r.puts, *nfo)
	return storage.Written{Namespace: "krateo-system", Name: name, Verb: "create", StatusCode: 201}, nil
}

// AsPrincipal reaches the store; a login that passes none hands it none.
func TestAsPrincipalReachesTheStore(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	cli, _ := fakeSigner(t)
	st := &recordingStore{}
	gen := NewGenerator(&rest.Config{}, Naming(exact), CAData("ca"), KubernetesURL("https://k8s.example"), CertDuration(time.Hour),
		Log(zerolog.Nop()), Lookup(&namesLookup{}), Storage(st)).(*kubeconfigGenerator)
	gen.csrClient = cli
	_, err := gen.Generate(storage.StrategyServiceAccount, userAs("cdc-x", "ns", "sa", "tenants"), AsPrincipal("agent"))
	require.NoError(t, err)
	_, err = gen.Generate(storage.StrategyOIDC, userAs(userX, "kc", "x"))
	require.NoError(t, err)
	require.Len(t, st.puts, 2)
	assert.Equal(t, "agent", st.puts[0].Principal)
	assert.Empty(t, st.puts[1].Principal)
}

// A refusal's record names the Secret the issuance would have written: the
// exact one with exact naming, and none for a name that can't be exact (its
// legacy name may be another user's: audit's name_not_issued rule). With
// legacy naming it is main's.
func TestExactRefusalNamesTheExactSecretOrNone(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	for _, tc := range []struct {
		naming   storage.Naming
		strategy storage.Strategy
		user     string
		want     string
	}{
		{exact, storage.StrategyOIDC, userX, exactX},
		{exact, storage.StrategyOIDC, "Alice.Smith", ""},
		{exact, storage.StrategyBasic, "Alice.Smith", ""},
		{storage.Naming{}, storage.StrategyOIDC, userX, sharedY},
		{storage.Naming{}, storage.StrategyBasic, "Alice.Smith", "alicesmith-clientconfig"},
	} {
		gen := &kubeconfigGenerator{lookup: &namesLookup{}, log: zerolog.Nop(), naming: tc.naming}
		// A system: group is refused before the guard, whatever the strategy.
		issued, err := gen.Generate(tc.strategy, userAs(tc.user, "kc", "1", "system:masters"))
		require.Error(t, err)
		assert.Equal(t, "krateo-system", issued.Secret.Namespace)
		assert.Equal(t, tc.want, issued.Secret.Name, "%v %s %q", tc.naming.Exact, tc.strategy, tc.user)
	}
	gen := &kubeconfigGenerator{lookup: &namesLookup{}, log: zerolog.Nop(), naming: exact}
	issued, err := gen.Generate(storage.StrategyLDAP, userAs("Alice.Smith", "corp", "uid=alice"))
	require.Equal(t, RefusalNotIssued, RefusalOf(err))
	assert.Empty(t, issued.Secret.Name)
	assert.Empty(t, issued.Secret.Verb)
}

// /usernames/check with exact naming (CheckUsernameWith), the X/Y pair
// included: a Secret under either name makes the name unavailable.
func TestCheckUsernameWithExactNaming(t *testing.T) {
	ctx := context.Background()
	claimed := map[string]string{storage.ClaimAnnotation: "c"}
	for _, tc := range []struct {
		name     string
		username string
		secrets  func(t *testing.T) map[string]*corev1.Secret
		lookup   namesLookup
		want     Unavailable
		reads    []string
	}{
		{"a dotted name nobody holds is available", userX, nil, namesLookup{}, "", []string{exactX, sharedY, "provisioned", "bound"}},
		{"a name that can't be exact is invalid", "Alice.Smith", nil, namesLookup{}, UnavailableInvalid, nil},
		{"a reserved name", "admin", nil, namesLookup{}, UnavailableReserved, nil},
		{"X/Y: johndoe's Secret under john.doe's legacy name makes it unavailable", userX, func(t *testing.T) map[string]*corev1.Secret {
			return map[string]*corev1.Secret{sharedY: ownedBy(t, sharedY, userY, claimed)}
		}, namesLookup{}, UnavailableHeldLegacy, []string{exactX, sharedY}},
		{"X/Y: john.doe's legacy Secret under johndoe's name", userY, func(t *testing.T) map[string]*corev1.Secret {
			return map[string]*corev1.Secret{sharedY: ownedBy(t, sharedY, userX, claimed)}
		}, namesLookup{}, UnavailableClaimed, []string{sharedY}},
		{"its own legacy Secret, claimed", userX, func(t *testing.T) map[string]*corev1.Secret {
			return map[string]*corev1.Secret{sharedY: ownedBy(t, sharedY, userX, claimed)}
		}, namesLookup{}, UnavailableClaimed, []string{exactX, sharedY}},
		{"its exact Secret, unclaimed", userX, func(t *testing.T) map[string]*corev1.Secret {
			return map[string]*corev1.Secret{exactX: ownedBy(t, exactX, userX, nil)}
		}, namesLookup{}, UnavailableHeldLegacy, []string{exactX}},
		{"provisioned", userX, nil, namesLookup{provisioned: true}, UnavailableProvisioned, []string{exactX, sharedY, "provisioned"}},
		{"bound", userX, nil, namesLookup{bound: true}, UnavailableBound, []string{exactX, sharedY, "provisioned", "bound"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := tc.lookup
			if tc.secrets != nil {
				l.secrets = tc.secrets(t)
			}
			why, err := CheckUsernameWith(ctx, &l, exact, tc.username)
			require.NoError(t, err)
			assert.Equal(t, tc.want, why)
			assert.Equal(t, tc.reads, l.asked)
		})
	}

	// Legacy naming: a dotted name is invalid, as main answers.
	why, err := CheckUsernameWith(ctx, &namesLookup{}, storage.Naming{}, userX)
	require.NoError(t, err)
	assert.Equal(t, UnavailableInvalid, why)
	why, err = CheckUsername(ctx, &fakeLookup{secret: secretWith(nil)}, userY)
	require.NoError(t, err)
	assert.Equal(t, UnavailableHeldLegacy, why)
}
