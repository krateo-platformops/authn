package storage

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// secretsAPI is an apiserver holding Secrets by name in krateo-system. It
// records every request, and every Secret body written, so a test can prove
// what was and wasn't touched.
type secretsAPI struct {
	mu       sync.Mutex
	stored   map[string]corev1.Secret
	requests []string // "METHOD name"
	written  []corev1.Secret
	// afterGet, when set, runs after a read is answered: another writer
	// acting between Put's read and its update.
	afterGet func(a *secretsAPI)
}

func newSecretsAPI(t *testing.T, existing ...corev1.Secret) (*secretsAPI, *rest.Config) {
	t.Helper()
	a := &secretsAPI{stored: map[string]corev1.Secret{}}
	for _, s := range existing {
		a.stored[s.Name] = s
	}
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
			a.written = append(a.written, sec)
		}
		a.requests = append(a.requests, r.Method+" "+name)
		notFound := func() {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
		}
		have, exists := a.stored[name]
		switch r.Method {
		case http.MethodGet:
			if !exists {
				notFound()
				return
			}
			_ = json.NewEncoder(w).Encode(have)
			if a.afterGet != nil {
				a.afterGet(a)
			}
		case http.MethodPost:
			if exists {
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"AlreadyExists","code":409}`)
				return
			}
			sec.UID, sec.ResourceVersion = k8stypes.UID("uid-"+name), "1"
			a.stored[name] = sec
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(sec)
		case http.MethodPut:
			if !exists {
				notFound()
				return
			}
			// As the apiserver does: an update naming a resourceVersion
			// replaces only that version.
			if sec.ResourceVersion != "" && sec.ResourceVersion != have.ResourceVersion {
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Conflict","code":409}`)
				return
			}
			sec.UID, sec.ResourceVersion = have.UID, have.ResourceVersion+"+"
			a.stored[name] = sec
			_ = json.NewEncoder(w).Encode(sec)
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return a, &rest.Config{Host: srv.URL}
}

// writes is the names of the Secrets a was asked to create or replace.
func (a *secretsAPI) writes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, r := range a.requests {
		if strings.HasPrefix(r, "POST ") || strings.HasPrefix(r, "PUT ") {
			out = append(out, strings.SplitN(r, " ", 2)[1])
		}
	}
	return out
}

// sessionSecret is a session Secret authn wrote for username, before
// authn#140 (no username annotation: ownership is the certificate's CN),
// optionally claimed.
func sessionSecret(t *testing.T, name, username, claim string) corev1.Secret {
	ann := map[string]string{StrategyAnnotation: "oidc"}
	if claim != "" {
		ann[ClaimAnnotation] = claim
	}
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "krateo-system", Annotations: ann, UID: k8stypes.UID("uid-" + name), ResourceVersion: "1"},
		Data:       map[string][]byte{ClientCertLabel: []byte(identityCert(t, username, []string{"devs"}))},
	}
}

func nfoFor(t *testing.T, strategy Strategy, username, claim string, groups ...string) *AuthInfo {
	return &AuthInfo{Strategy: strategy, Claim: claim, CertData: identityCert(t, username, groups), KeyData: "k", CAData: "ca", Server: "s"}
}

// Flag off, Put writes what authn always has: the legacy name, no username
// annotation and no labels.
func TestPutWithLegacyNamingIsUnchanged(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	for _, store := range []func(*rest.Config) AuthInfoStorage{
		Default,
		func(rc *rest.Config) AuthInfoStorage { return NewStore(rc, Naming{}) },
	} {
		api, rc := newSecretsAPI(t)
		w, err := store(rc).Put(userX, nfoFor(t, StrategyOIDC, userX, "c"))
		require.NoError(t, err)
		assert.Equal(t, "johndoe-clientconfig", w.Name)
		require.Len(t, api.written, 1)
		sec := api.written[0]
		assert.Nil(t, sec.Labels, "no labels")
		keys := []string{}
		for k := range sec.Annotations {
			keys = append(keys, k)
		}
		assert.ElementsMatch(t, []string{NotBeforeAnnotation, NotAfterAnnotation, StrategyAnnotation, GroupsAnnotation, ClaimAnnotation}, keys)
	}
}

// Flag on, a session Secret is written under the exact name with the username
// annotation and both labels, whatever the strategy; the principal follows
// the strategy, and a mapping's is its declared kind, never human, even with
// the tenants group.
func TestPutWithExactNaming(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	for _, tc := range []struct {
		strategy  Strategy
		username  string
		principal string // AuthInfo.Principal
		groups    []string
		name      string
		wantPrinc string
		wantLabel string
	}{
		{StrategyBasic, userX, "", nil, "john.doe-clientconfig", "human", "john-doe--30f69670bba2"},
		{StrategyLDAP, userX, "", nil, "john.doe-clientconfig", "human", "john-doe--30f69670bba2"},
		{StrategyOAuth, userY, "", nil, "johndoe-clientconfig", "human", "johndoe"},
		{StrategyOIDC, userY, "", []string{"tenants"}, "johndoe-clientconfig", "human", "johndoe"},
		{StrategyServiceAccount, "cdc-x", "", []string{"tenants"}, "cdc-x-clientconfig", "service", "cdc-x"},
		{StrategyServiceAccount, "cdc-x", "agent", nil, "cdc-x-clientconfig", "agent", "cdc-x"},
		{StrategyServiceAccount, "cdc-x", "controller", nil, "cdc-x-clientconfig", "controller", "cdc-x"},
		{StrategyServiceAccount, "cdc-x", "human", []string{"tenants"}, "cdc-x-clientconfig", "service", "cdc-x"},
	} {
		t.Run(string(tc.strategy)+"/"+tc.username+"/"+tc.principal, func(t *testing.T) {
			api, rc := newSecretsAPI(t)
			nfo := nfoFor(t, tc.strategy, tc.username, "claim", tc.groups...)
			nfo.Principal = tc.principal
			w, err := NewStore(rc, exactNaming).Put(tc.username, nfo)
			require.NoError(t, err)
			assert.Equal(t, tc.name, w.Name)
			assert.Equal(t, []string{tc.name}, api.writes())
			sec := api.written[0]
			assert.Equal(t, tc.username, sec.Annotations[UsernameAnnotation], "the authenticated username")
			assert.Equal(t, map[string]string{PrincipalLabel: tc.wantPrinc, UsernameLabelLabel: tc.wantLabel}, sec.Labels)
			// The existing annotations are kept.
			for _, k := range []string{StrategyAnnotation, GroupsAnnotation, ClaimAnnotation, NotAfterAnnotation, NotBeforeAnnotation} {
				assert.Contains(t, sec.Annotations, k)
			}
		})
	}
}

// A step-up Secret is <username>-clientconfig-stepup exactly, with the same
// identity keys.
func TestPutStepUpWithExactNaming(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	api, rc := newSecretsAPI(t)
	nfo := nfoFor(t, StrategyOIDC, userX, "claim", "krateo:loa:2")
	nfo.StepUp = true
	w, err := NewStore(rc, exactNaming).Put(userX, nfo)
	require.NoError(t, err)
	assert.Equal(t, "john.doe-clientconfig-stepup", w.Name)
	assert.Equal(t, []string{"john.doe-clientconfig-stepup"}, api.writes(), "the legacy step-up name is never written")
	assert.Equal(t, userX, api.written[0].Annotations[UsernameAnnotation])
	assert.Equal(t, "human", api.written[0].Labels[PrincipalLabel])
}

// An administrator-provisioned name that can't be exact keeps its legacy
// name, and still carries the identity keys.
func TestPutKeepsTheLegacyNameOfAProvisionedNameThatCantBeExact(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	const username = "Pinco.Pallo@kubeworld.it"
	api, rc := newSecretsAPI(t)
	w, err := NewStore(rc, exactNaming).Put(username, nfoFor(t, StrategyBasic, username, "claim"))
	require.NoError(t, err)
	assert.Equal(t, ClientConfigSecretName(username), w.Name)
	assert.Equal(t, username, api.written[0].Annotations[UsernameAnnotation])
	assert.Equal(t, "human", api.written[0].Labels[PrincipalLabel])
	assert.NotContains(t, api.written[0].Labels, UsernameLabelLabel, "Bounded gives no valid label value for a name starting uppercase: none is stamped")
}

// The X/Y pair at the writer. john.doe writes john.doe-clientconfig only, and
// johndoe's johndoe-clientconfig is never read for the write, let alone
// replaced. johndoe, whose exact name holds john.doe's legacy Secret, is
// refused, and that Secret is left as it was.
func TestPutXYNeverTouchesTheOtherUsersSecret(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")

	ySecret := sessionSecret(t, "johndoe-clientconfig", userY, `["oidc","kc","y"]`)
	api, rc := newSecretsAPI(t, ySecret)
	_, err := NewStore(rc, exactNaming).Put(userX, nfoFor(t, StrategyOIDC, userX, `["oidc","kc","x"]`))
	require.NoError(t, err)
	assert.Equal(t, []string{"john.doe-clientconfig"}, api.writes())
	assert.Equal(t, ySecret, api.stored["johndoe-clientconfig"], "johndoe's Secret is untouched")
	for _, r := range api.requests {
		assert.NotContains(t, r, "johndoe-clientconfig", "the legacy name isn't even read")
	}

	// johndoe signs in while johndoe-clientconfig is john.doe's legacy Secret.
	xLegacy := sessionSecret(t, "johndoe-clientconfig", userX, `["oidc","kc","x"]`)
	for _, claim := range []string{`["oidc","kc","x"]`, `["oidc","kc","y"]`, ""} {
		api, rc = newSecretsAPI(t, xLegacy)
		w, err := NewStore(rc, exactNaming).Put(userY, nfoFor(t, StrategyOIDC, userY, claim))
		require.ErrorIs(t, err, ErrClaimedByAnother, "claim %q: another username's Secret is never replaced, whatever its claim", claim)
		assert.Equal(t, Written{Namespace: "krateo-system", Name: "johndoe-clientconfig", Verb: "update"}, w)
		assert.Equal(t, xLegacy, api.stored["johndoe-clientconfig"], "john.doe's legacy Secret is untouched")
		assert.Len(t, api.written, 1, "only the create the apiserver refused")
	}

	// Legacy naming replaces it as authn always has, when the claim allows.
	api, rc = newSecretsAPI(t, xLegacy)
	_, err = Default(rc).Put(userY, nfoFor(t, StrategyOIDC, userY, `["oidc","kc","x"]`))
	require.NoError(t, err)
}

// The user's own Secret under the exact name is updated: owned by its
// annotation or, written before authn#140, by its certificate's CN.
func TestPutUpdatesTheUsersOwnExactSecret(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	byCN := sessionSecret(t, "john.doe-clientconfig", userX, "c")
	byAnnotation := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "john.doe-clientconfig", Namespace: "krateo-system",
		Annotations: map[string]string{UsernameAnnotation: userX, ClaimAnnotation: "c"}}}
	for _, have := range []corev1.Secret{byCN, byAnnotation} {
		api, rc := newSecretsAPI(t, have)
		w, err := NewStore(rc, exactNaming).Put(userX, nfoFor(t, StrategyOIDC, userX, "c"))
		require.NoError(t, err)
		assert.Equal(t, "update", w.Verb)
		assert.Equal(t, []string{"john.doe-clientconfig", "john.doe-clientconfig"}, api.writes())
	}
	// A claim of another identity on it still refuses the write.
	api, rc := newSecretsAPI(t, byCN)
	_, err := NewStore(rc, exactNaming).Put(userX, nfoFor(t, StrategyOIDC, userX, "other"))
	require.ErrorIs(t, err, ErrClaimedByAnother)
	assert.Len(t, api.written, 1)
}

// A provisioned name that can't be exact (240 characters) keeps its legacy
// name, which is another user's exact name (its first 63 characters). Its
// write is refused and that Secret left untouched, claimed or not: the owner
// of a legacy-named target is checked as an exact one's is (review of #147).
func TestPutRefusesALegacyNamedTargetHeldByAnother(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	long := strings.Repeat("a", 63) + strings.Repeat("b", 177) // 240 > 233
	other := strings.Repeat("a", 63)
	require.False(t, exactNaming.Issuable(long))
	legacy := ClientConfigSecretName(long)
	require.Equal(t, other+"-clientconfig", legacy)
	for _, claim := range []string{"", `["oidc","kc","o"]`} {
		have := sessionSecret(t, legacy, other, claim)
		api, rc := newSecretsAPI(t, have)
		_, err := NewStore(rc, exactNaming).Put(long, nfoFor(t, StrategyBasic, long, `["basic","","p"]`))
		want := ErrHeldByAnother // no claim: name_held_legacy, as the guard refuses it
		if claim != "" {
			want = ErrClaimedByAnother
		}
		require.ErrorIs(t, err, want, "claim %q", claim)
		assert.Equal(t, have, api.stored[legacy])
		assert.Len(t, api.written, 1, "only the refused create")
	}
}

// The update replaces exactly the Secret Put proved the username's: if it is
// deleted and re-created by another identity between the read and the
// update, the update is a conflict, and the newcomer's Secret stays.
func TestPutUpdateIsConditionalOnTheSecretItChecked(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := sessionSecret(t, "john.doe-clientconfig", userX, "c")
	theirs := sessionSecret(t, "john.doe-clientconfig", "mallory", "m")
	theirs.ResourceVersion = "9"
	api, rc := newSecretsAPI(t, mine)
	api.afterGet = func(a *secretsAPI) { a.stored["john.doe-clientconfig"] = theirs }
	w, err := NewStore(rc, exactNaming).Put(userX, nfoFor(t, StrategyOIDC, userX, "c"))
	require.Error(t, err)
	assert.Equal(t, "update", w.Verb)
	assert.Equal(t, 409, w.StatusCode)
	assert.Equal(t, theirs, api.stored["john.doe-clientconfig"], "never overwritten")
	require.Len(t, api.written, 2)
	assert.Equal(t, "1", api.written[1].ResourceVersion, "the update names the version it checked")

	// Legacy naming sends no precondition, as authn always has.
	api, rc = newSecretsAPI(t, sessionSecret(t, "johndoe-clientconfig", userY, "c"))
	_, err = Default(rc).Put(userY, nfoFor(t, StrategyOIDC, userY, "c"))
	require.NoError(t, err)
	assert.Empty(t, api.written[1].ResourceVersion)
}

// The labels go on the update too, not only on a create.
func TestPutStampsTheLabelsOnAnUpdate(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	api, rc := newSecretsAPI(t, sessionSecret(t, "john.doe-clientconfig", userX, "c"))
	w, err := NewStore(rc, exactNaming).Put(userX, nfoFor(t, StrategyOIDC, userX, "c"))
	require.NoError(t, err)
	require.Equal(t, "update", w.Verb)
	stored := api.stored["john.doe-clientconfig"]
	assert.Equal(t, map[string]string{PrincipalLabel: "human", UsernameLabelLabel: "john-doe--30f69670bba2"}, stored.Labels)
	assert.Equal(t, userX, stored.Annotations[UsernameAnnotation])
}
