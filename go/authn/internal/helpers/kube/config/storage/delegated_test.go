package storage

import (
	"errors"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/plumbing/endpoints"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// asRead is sec as a reader gets it back: what was sent as StringData is
// Data.
func asRead(sec corev1.Secret) *corev1.Secret {
	out := sec.DeepCopy()
	if out.Data == nil {
		out.Data = map[string][]byte{}
	}
	for k, v := range sec.StringData {
		out.Data[k] = []byte(v)
	}
	out.StringData = nil
	return out
}

func delegatedNfo(t *testing.T, username, actor string, groups ...string) *AuthInfo {
	nfo := nfoFor(t, StrategyOIDC, username, "claim-"+username, groups...)
	nfo.Actor = actor
	return nfo
}

// authn#167: a delegated credential is its own Secret, named for the person
// and the actor, whatever the naming mode. It is the token's by the very
// check snowplow runs (endpoints.CheckDelegatedCredential), carries the
// identity annotations, and none of the labels the tenant policy selects
// sign-ins by. The session Secret is never touched.
func TestPutDelegated(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store func(*testing.T) (*secretsAPI, AuthInfoStorage)
	}{
		{"legacy naming", func(t *testing.T) (*secretsAPI, AuthInfoStorage) {
			api, rc := newSecretsAPI(t, sessionSecret(t, "alice-clientconfig", "alice", "claim-alice"))
			return api, Default(rc)
		}},
		{"exact naming", func(t *testing.T) (*secretsAPI, AuthInfoStorage) {
			api, rc := newSecretsAPI(t, sessionSecret(t, "alice-clientconfig", "alice", "claim-alice"))
			return api, NewStore(rc, exactNaming)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(util.NamespaceEnvVar, "krateo-system")
			api, st := tc.store(t)
			w, err := st.Put("alice", delegatedNfo(t, "alice", "dispatcher", "devs", "ops"))
			require.NoError(t, err)

			name := endpoints.DelegatedSecretName("alice", "dispatcher", []string{"ops", "devs"})
			assert.Equal(t, name, w.Name)
			assert.Equal(t, "create", w.Verb)
			assert.Equal(t, "krateo-system", w.Namespace)
			assert.Equal(t, []string{name}, api.writes(), "only the delegated Secret is written")

			sec := api.stored[name]
			assert.Equal(t, endpoints.DelegatedCredentialHeld,
				endpoints.CheckDelegatedCredential(asRead(sec), "alice", "dispatcher", []string{"ops", "devs"}, time.Now()))
			assert.Equal(t, "alice", sec.Annotations[UsernameAnnotation])
			assert.Equal(t, "dispatcher", sec.Annotations[endpoints.ActorAnnotation])
			assert.Equal(t, "claim-alice", sec.Annotations[ClaimAnnotation])
			assert.Equal(t, "oidc", sec.Annotations[StrategyAnnotation])
			assert.ElementsMatch(t, []string{"devs", "ops"}, SplitGroups(sec.Annotations[GroupsAnnotation]))
			assert.NotEmpty(t, sec.Annotations[NotAfterAnnotation])
			assert.Empty(t, sec.Labels, "no principal or username label: an exchange isn't a sign-in")
			assert.Empty(t, sec.OwnerReferences)
		})
	}
}

// Each exchange through the same actor for the same person with the same
// groups replaces its Secret, conditionally on the version it read. Another
// actor's is another Secret, and so is another set of groups: a client may
// still hold the first one's token.
func TestPutDelegatedReplacesOnlyItsOwn(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	api, rc := newSecretsAPI(t)
	st := Default(rc)
	put := func(actor string, groups ...string) (string, Written) {
		t.Helper()
		w, err := st.Put("alice", delegatedNfo(t, "alice", actor, groups...))
		require.NoError(t, err)
		assert.Equal(t, endpoints.DelegatedSecretName("alice", actor, groups), w.Name)
		return w.Name, w
	}
	mine, _ := put("dispatcher", "devs")
	other, _ := put("ide-agent", "devs")
	more, w := put("dispatcher", "devs", "ops")
	assert.Equal(t, "create", w.Verb, "other groups are another Secret")
	none, w := put("dispatcher")
	assert.Equal(t, "create", w.Verb, "and so are none")

	before := api.stored[mine]
	again, w := put("dispatcher", "devs")
	assert.Equal(t, mine, again)
	assert.Equal(t, "update", w.Verb)
	assert.Equal(t, "1", api.written[len(api.written)-1].ResourceVersion, "the update names the version it read")
	assert.NotEqual(t, before, api.stored[mine], "replaced")

	for name, tc := range map[string]struct {
		actor  string
		groups []string
	}{
		mine:  {"dispatcher", []string{"devs"}},
		other: {"ide-agent", []string{"devs"}},
		more:  {"dispatcher", []string{"ops", "devs"}},
		none:  {"dispatcher", nil},
	} {
		assert.Equal(t, endpoints.DelegatedCredentialHeld,
			endpoints.CheckDelegatedCredential(asRead(api.stored[name]), "alice", tc.actor, tc.groups, time.Now()),
			"%s with %v is still held", tc.actor, tc.groups)
	}
	assert.Len(t, api.stored, 4)
}

// A Secret under the name that isn't this person's and actor's is never
// replaced, and one replaced between the read and the update is a conflict.
func TestPutDelegatedNeverReplacesAnothers(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	name := endpoints.DelegatedSecretName("alice", "dispatcher", []string{"devs"})
	for _, ann := range []map[string]string{
		{UsernameAnnotation: "bob", endpoints.ActorAnnotation: "dispatcher"},
		{UsernameAnnotation: "alice", endpoints.ActorAnnotation: "ide-agent"},
		nil,
	} {
		theirs := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "krateo-system", Annotations: ann,
			UID: k8stypes.UID("uid-theirs"), ResourceVersion: "4"}}
		api, rc := newSecretsAPI(t, theirs)
		w, err := Default(rc).Put("alice", delegatedNfo(t, "alice", "dispatcher", "devs"))
		require.ErrorIs(t, err, ErrHeldByAnother)
		assert.Equal(t, "update", w.Verb)
		assert.Equal(t, theirs, api.stored[name], "never overwritten")
	}

	mine := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "krateo-system", ResourceVersion: "1",
		Annotations: map[string]string{UsernameAnnotation: "alice", endpoints.ActorAnnotation: "dispatcher"}}}
	newer := mine
	newer.ResourceVersion = "9"
	api, rc := newSecretsAPI(t, mine)
	api.afterGet = func(a *secretsAPI) { a.stored[name] = newer }
	w, err := Default(rc).Put("alice", delegatedNfo(t, "alice", "dispatcher", "devs"))
	require.Error(t, err)
	assert.Equal(t, 409, w.StatusCode)
	assert.Equal(t, newer, api.stored[name])
}

// A delegated credential is neither a step-up credential nor owned.
func TestPutDelegatedRefusesSignInOptions(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	for _, set := range []func(*AuthInfo){
		func(n *AuthInfo) { n.StepUp = true },
		func(n *AuthInfo) { n.Owner = &metav1.OwnerReference{Name: "mapping"} },
	} {
		api, rc := newSecretsAPI(t)
		nfo := delegatedNfo(t, "alice", "dispatcher", "devs")
		set(nfo)
		_, err := Default(rc).Put("alice", nfo)
		require.True(t, errors.Is(err, errDelegatedOptions), err)
		assert.Empty(t, api.writes())
	}
}

func TestDelegatedSecretNames(t *testing.T) {
	name := DelegatedSecretName("alice", "dispatcher", []string{"devs"})
	assert.Equal(t, endpoints.DelegatedSecretName("alice", "dispatcher", []string{"devs"}), name)
	assert.True(t, IsDelegatedSecretName(name))
	assert.False(t, IsDelegatedSecretName("alice-clientconfig"))
	assert.False(t, IsStepUpSecretName(name))
}
