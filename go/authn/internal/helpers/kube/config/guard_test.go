package config

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeLookup answers the name guard from fixed facts and counts what it was
// asked, so a test can tell a refusal decided early from one decided late.
type fakeLookup struct {
	secret      *corev1.Secret
	provisioned bool
	bound       bool
	err         error

	asked []string
}

func (f *fakeLookup) SessionSecret(_ context.Context, _ string) (*corev1.Secret, error) {
	f.asked = append(f.asked, "secret")
	return f.secret, f.err
}

func (f *fakeLookup) Provisioned(_ context.Context, _ string) (bool, error) {
	f.asked = append(f.asked, "provisioned")
	return f.provisioned, f.err
}

func (f *fakeLookup) BoundAsUser(_ context.Context, _ string) (bool, error) {
	f.asked = append(f.asked, "bound")
	return f.bound, f.err
}

func secretWith(annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "x-clientconfig", Annotations: annotations}}
}

func userAs(name, issuer, id string, groups ...string) *userinfo.DefaultUser {
	u := userinfo.NewDefaultUser(name, "random", groups, nil)
	u.Subject = userinfo.Subject{Issuer: issuer, ID: id}
	return u
}

// The guard's decision table. Every refusal is 403 UsernameUnavailable; a
// lookup that fails is authn's failure, 500 IssuanceFailed.
func TestNameGuard(t *testing.T) {
	github := func(name, id string) *userinfo.DefaultUser { return userAs(name, "github", id) }
	claimOf := func(s storage.Strategy, u *userinfo.DefaultUser) string {
		return storage.EncodeClaim(s, u.Subject.Issuer, u.Subject.ID)
	}
	alice := github("alice", "1001")
	mallory := github("alice", "6666") // another GitHub account, same login after a rename
	admin := userAs("admin", "krateo-system", "admin")

	tests := []struct {
		name     string
		strategy storage.Strategy
		user     *userinfo.DefaultUser
		lookup   fakeLookup
		code     int // 0: admitted
		cause    status.CauseType
	}{
		{name: "a new identity-source name nobody holds", strategy: storage.StrategyOAuth, user: alice},
		{name: "a name claimed by the same identity", strategy: storage.StrategyOAuth, user: alice,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: claimOf(storage.StrategyOAuth, alice)}), bound: true}},
		{name: "a name claimed by another identity of the same source", strategy: storage.StrategyOAuth, user: mallory,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: claimOf(storage.StrategyOAuth, alice)})},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "the same subject through another strategy is another identity", strategy: storage.StrategyOIDC, user: alice,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: claimOf(storage.StrategyOAuth, alice)})},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "a pre-claim Secret its own strategy wrote is adopted", strategy: storage.StrategyOAuth, user: alice,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "oauth"}), bound: true}},
		{name: "a pre-claim Secret another strategy wrote", strategy: storage.StrategyOAuth, user: alice,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "basic"})},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "an identity source can't adopt a Secret of unknown origin", strategy: storage.StrategyOIDC, user: alice,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "unknown"})},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "an identity source can't adopt an unannotated Secret", strategy: storage.StrategyOIDC, user: alice,
			lookup: fakeLookup{secret: secretWith(nil)},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "a provisioned identity adopts a Secret of unknown origin", strategy: storage.StrategyBasic, user: admin,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "unknown"})}},
		{name: "a provisioned identity adopts an unannotated Secret", strategy: storage.StrategyServiceAccount, user: admin,
			lookup: fakeLookup{secret: secretWith(nil)}},
		{name: "a provisioned identity can't take a name an identity source holds", strategy: storage.StrategyBasic, user: admin,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "oauth"})},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "a provisioned identity's first login, even where bindings name it", strategy: storage.StrategyBasic, user: admin,
			lookup: fakeLookup{bound: true}},
		{name: "a name an RBAC binding grants rights to", strategy: storage.StrategyOAuth, user: github("ops-robot", "7"),
			lookup: fakeLookup{bound: true}, code: 403, cause: status.CauseUsernameUnavailable},
		{name: "a name an administrator provisioned", strategy: storage.StrategyLDAP, user: userAs("snowplow-seed", "corp", "cn=x"),
			lookup: fakeLookup{provisioned: true}, code: 403, cause: status.CauseUsernameUnavailable},
		{name: "a reserved name", strategy: storage.StrategyOAuth, user: github("kube-proxy", "8"),
			code: 403, cause: status.CauseUsernameUnavailable},
		{name: "a reserved name, even when claimed before", strategy: storage.StrategyOIDC, user: userAs("admin", "kc", "9"),
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: storage.EncodeClaim(storage.StrategyOIDC, "kc", "9")})},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "no username", strategy: storage.StrategyOIDC, user: userAs("", "kc", "9"),
			code: 403, cause: status.CauseUsernameUnavailable},
		{name: "no subject", strategy: storage.StrategyOIDC, user: userAs("alice", "kc", ""),
			code: 500, cause: status.CauseIssuanceFailed},
		{name: "the Secret can't be read", strategy: storage.StrategyOAuth, user: alice,
			lookup: fakeLookup{err: errors.New("apiserver down")}, code: 500, cause: status.CauseIssuanceFailed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := nameGuard{lookup: &tc.lookup, log: zerolog.Nop()}
			claim, err := g.admit(context.Background(), tc.strategy, tc.user)
			if tc.code == 0 {
				require.NoError(t, err)
				assert.Equal(t, claimOf(tc.strategy, tc.user), claim)
				return
			}
			require.Error(t, err)
			assert.Empty(t, claim)
			st := status.FromError(err)
			assert.Equal(t, tc.code, st.Code)
			require.NotNil(t, st.Details)
			assert.Equal(t, tc.cause, st.Details.Causes[0].Type)
		})
	}
}

// A refusal doesn't tell the caller why: a probe can't learn which names the
// cluster grants rights to, or who holds a name.
func TestNameGuardRefusalIsOpaque(t *testing.T) {
	for _, lookup := range []fakeLookup{
		{bound: true},
		{provisioned: true},
		{secret: secretWith(map[string]string{storage.ClaimAnnotation: `["oauth","github","1"]`})},
	} {
		g := nameGuard{lookup: &lookup, log: zerolog.Nop()}
		_, err := g.admit(context.Background(), storage.StrategyOAuth, userAs("alice", "github", "2"))
		st := status.FromError(err)
		assert.Equal(t, `the username "alice" isn't available to this identity`, st.Details.Causes[0].Message)
	}
}

// Only an identity source's first claim pays for the cluster-wide reads; a
// name already claimed by the caller is decided from its Secret alone.
func TestNameGuardReadsOnlyWhatItNeeds(t *testing.T) {
	alice := userAs("alice", "github", "1001")
	claimed := fakeLookup{secret: secretWith(map[string]string{
		storage.ClaimAnnotation: storage.EncodeClaim(storage.StrategyOAuth, "github", "1001")})}
	g := nameGuard{lookup: &claimed, log: zerolog.Nop()}
	_, err := g.admit(context.Background(), storage.StrategyOAuth, alice)
	require.NoError(t, err)
	assert.Equal(t, []string{"secret"}, claimed.asked)

	fresh := fakeLookup{}
	g = nameGuard{lookup: &fresh, log: zerolog.Nop()}
	_, err = g.admit(context.Background(), storage.StrategyOAuth, alice)
	require.NoError(t, err)
	assert.Equal(t, []string{"secret", "provisioned", "bound"}, fresh.asked)
}

// Kubernetes reserves `system:` groups for identities the apiserver vouches
// for. No login may put one in a certificate, whatever its source; other
// groups, such as one a Keycloak claim asserts, pass.
func TestSystemGroupsAreRefused(t *testing.T) {
	for _, g := range []string{"system:masters", "system:nodes", "system:bootstrappers", "system:"} {
		err := checkSystemGroups(userAs("alice", "kc", "1", "tenants", g))
		st := status.FromError(err)
		assert.Equal(t, http.StatusForbidden, st.Code, g)
		assert.Equal(t, status.CauseSystemGroupNotAllowed, st.Details.Causes[0].Type, g)
	}
	require.NoError(t, checkSystemGroups(userAs("alice", "kc", "1", "tenants", "krateo:devs", "systems-team")))
}

// The cluster lookup finds a User subject in a ClusterRoleBinding or in a
// RoleBinding of any namespace, ignores Groups and ServiceAccounts of the same
// name, and reads the session Secret from authn's namespace.
func TestClusterLookup(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	cli := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "ops-robot-admin"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "ops-robot"}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "tenant-team-a"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "team-a"}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "group-and-sa", Namespace: "ns"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "devs"}, {Kind: rbacv1.ServiceAccountKind, Name: "bob", Namespace: "ns"}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-clientconfig", Namespace: "krateo-system"}},
	)
	l := &clusterLookup{cli: cli}
	ctx := context.Background()

	for name, want := range map[string]bool{"ops-robot": true, "team-a": true, "devs": false, "bob": false, "alice": false} {
		got, err := l.BoundAsUser(ctx, name)
		require.NoError(t, err)
		assert.Equal(t, want, got, name)
	}

	sec, err := l.SessionSecret(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, sec)
	assert.Equal(t, "alice-clientconfig", sec.Name)

	sec, err = l.SessionSecret(ctx, "nobody")
	require.NoError(t, err)
	assert.Nil(t, sec)
}
