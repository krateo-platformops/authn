package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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

func (f *fakeLookup) Secret(_ context.Context, _ string) (*corev1.Secret, error) {
	f.asked = append(f.asked, "target")
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

// issuedTo is secretWith holding a client certificate issued to cn, as authn
// stores it (base64 of the PEM block): what a Secret written before claims
// existed proves its owner with.
func issuedTo(t testing.TB, cn string, annotations map[string]string) *corev1.Secret {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	sec := secretWith(annotations)
	sec.Data = map[string][]byte{storage.ClientCertLabel: []byte(base64.StdEncoding.EncodeToString(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))}
	return sec
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
			lookup: fakeLookup{secret: issuedTo(t, "alice", map[string]string{storage.StrategyAnnotation: "oauth"}), bound: true}},
		// The derived name aliases usernames (john.doe's Secret is
		// johndoe-clientconfig): an unclaimed Secret is adopted only by the
		// name its certificate was issued to.
		{name: "a pre-claim Secret its strategy wrote for another name isn't adopted", strategy: storage.StrategyOAuth, user: alice,
			lookup: fakeLookup{secret: issuedTo(t, "al.ice", map[string]string{storage.StrategyAnnotation: "oauth"})},
			code:   403, cause: status.CauseUsernameUnavailable},
		{name: "a pre-claim Secret with no certificate is no one's", strategy: storage.StrategyOAuth, user: alice,
			lookup: fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "oauth"})},
			code:   403, cause: status.CauseUsernameUnavailable},
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
			lookup: fakeLookup{secret: issuedTo(t, admin.GetUserName(), map[string]string{storage.StrategyAnnotation: "unknown"})}},
		{name: "a provisioned identity adopts an unannotated Secret", strategy: storage.StrategyServiceAccount, user: admin,
			lookup: fakeLookup{secret: issuedTo(t, admin.GetUserName(), nil)}},
		{name: "a provisioned identity doesn't adopt another name's unannotated Secret", strategy: storage.StrategyBasic, user: admin,
			lookup: fakeLookup{secret: issuedTo(t, admin.GetUserName()+".x", nil)},
			code:   403, cause: status.CauseUsernameUnavailable},
		// A synthetic Secret with no certificate (demo's acme, globex): no one
		// can prove it theirs, so a provisioned identity is refused too (acmp).
		{name: "a provisioned identity doesn't adopt a Secret with no certificate", strategy: storage.StrategyBasic, user: admin,
			lookup: fakeLookup{secret: secretWith(nil)},
			code:   403, cause: status.CauseUsernameUnavailable},
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

// A verified identity with no username is a refusal of that identity, like the
// guard's others, so its record is denied rather than failed (#127).
func TestAnIdentityWithoutAUsernameIsRefused(t *testing.T) {
	g := nameGuard{lookup: &fakeLookup{}, log: zerolog.Nop()}
	_, err := g.admit(context.Background(), storage.StrategyOIDC, userAs("", "kc", "9"))
	require.Error(t, err)
	assert.Equal(t, RefusalNameMissing, RefusalOf(err))
	assert.Equal(t, status.CauseUsernameUnavailable, status.FromError(err).Details.Causes[0].Type)
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
		assert.Equal(t, `the username isn't available to this identity`, st.Details.Causes[0].Message)
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

// The binding lookup reads every namespace's RoleBindings in one uncached
// List, and a List that fails is an error, never "not bound": an access-request
// controller relies on /usernames/check alone for bindings (acmp, 2026-11-12),
// so a lookup that answered false on a failed read would hand out a bound name.
func TestClusterLookupBindingsFailClosedAndSpanAllNamespaces(t *testing.T) {
	for _, failing := range []string{"clusterrolebindings", "rolebindings"} {
		t.Run(failing, func(t *testing.T) {
			cli := fake.NewSimpleClientset()
			var rbNamespaces []string
			cli.PrependReactor("list", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
				if a.GetResource().Resource == "rolebindings" {
					rbNamespaces = append(rbNamespaces, a.GetNamespace())
				}
				if a.GetResource().Resource == failing {
					return true, nil, errors.New("apiserver unavailable")
				}
				return false, nil, nil
			})
			got, err := (&clusterLookup{cli: cli}).BoundAsUser(context.Background(), "alice")
			require.Error(t, err)
			assert.False(t, got)
			if failing == "rolebindings" {
				assert.Equal(t, []string{metav1.NamespaceAll}, rbNamespaces,
					"RoleBindings must be listed once, across all namespaces")
			}
		})
	}
}

// An identity source may not assert a `krateo:` group: those carry platform
// rights and come only from identities an administrator provisions. authn's own
// step-up group isn't the source's (Diego, 2026-11-11).
func TestIdentitySourcesCantAssertPlatformGroups(t *testing.T) {
	for _, tc := range []struct {
		name     string
		strategy storage.Strategy
		groups   []string
		refused  bool
	}{
		{"an IdP asserting krateo:services", storage.StrategyOIDC, []string{"devs", "krateo:services"}, true},
		{"a directory asserting krateo:public", storage.StrategyLDAP, []string{"krateo:public"}, true},
		{"a RESTAction asserting krateo:cdc:x", storage.StrategyOAuth, []string{"krateo:cdc:x"}, true},
		{"authn's own step-up group", storage.StrategyOIDC, []string{"devs", "krateo:loa:2"}, false},
		{"a ServiceAccount mapping's platform group", storage.StrategyServiceAccount, []string{"krateo:services"}, false},
		{"a basic User's platform group", storage.StrategyBasic, []string{"krateo:admins"}, false},
		{"no krateo group", storage.StrategyOIDC, []string{"devs", "krateo"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := &userinfo.DefaultUser{Name: "alice", ID: "1", Groups: tc.groups}
			err := checkPlatformGroups(tc.strategy, user)
			if !tc.refused {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, RefusalPlatformGroup, RefusalOf(err))
			assert.Equal(t, status.CausePlatformGroupNotAllowed, status.FromError(err).Details.Causes[0].Type)
		})
	}
}

// A `krateo:` platform identity is never issued to an identity source, even
// one that issues names as-is (LDAP's uid): snowplow impersonates
// krateo:public and relies on it.
func TestPlatformIdentitiesAreNeverIssued(t *testing.T) {
	g := nameGuard{lookup: &fakeLookup{}, log: zerolog.Nop()}
	_, err := g.admit(context.Background(), storage.StrategyLDAP, userAs("krateo:public", "dir", "cn=public"))
	require.Error(t, err)
	assert.Equal(t, RefusalReserved, RefusalOf(err))
}

// Moving an existing name to a new identity without touching anything the name
// carries: an administrator writes the new identity's claim onto the EXISTING
// Secret (authn.krateo.io/claim, storage.EncodeClaim), and that identity's
// first sign-in adopts it. The Secret is rewritten in place, so whatever hangs
// off it survives (a tenant namespace a policy generates from it, say), and the
// bindings that name the user stay. Only the identity the claim names gets the
// name; any other, or none, is refused (docs/behavior.md, "Moving a name to a
// new identity").
func TestAnAdminClaimMovesALegacyNameToANewIdentity(t *testing.T) {
	kc := func(id string) *userinfo.DefaultUser {
		return userAs("braghettos", "https://kc.example/realms/krateo", id)
	}
	newcomer := kc("2f6c-new-sub")
	adminClaim := storage.EncodeClaim(storage.StrategyOIDC, newcomer.Subject.Issuer, newcomer.Subject.ID)
	legacy := func(extra map[string]string) *corev1.Secret {
		ann := map[string]string{storage.StrategyAnnotation: "oauth"} // written by the retired GitHub login
		for k, v := range extra {
			ann[k] = v
		}
		return secretWith(ann)
	}

	for _, tc := range []struct {
		name     string
		user     *userinfo.DefaultUser
		secret   *corev1.Secret
		admitted bool
	}{
		{"the identity the admin's claim names is admitted, though bindings name the user", newcomer, legacy(map[string]string{storage.ClaimAnnotation: adminClaim}), true},
		{"another sub with the same username is refused", kc("6666-other"), legacy(map[string]string{storage.ClaimAnnotation: adminClaim}), false},
		{"without the admin's claim the legacy Secret is refused", newcomer, legacy(nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := nameGuard{lookup: &fakeLookup{secret: tc.secret, bound: true}, log: zerolog.Nop()}
			claim, err := g.admit(context.Background(), storage.StrategyOIDC, tc.user)
			if !tc.admitted {
				require.Error(t, err)
				assert.Equal(t, status.CauseUsernameUnavailable, status.FromError(err).Details.Causes[0].Type)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, adminClaim, claim, "the claim the sign-in keeps is the admin's")
		})
	}
}

// The case the fix exists for, with the names it aliases: john.doe's
// pre-claim Secret is johndoe-clientconfig. Its owner, john.doe, adopts it;
// johndoe, whose name derives the same Secret, is refused as
// name_held_legacy, and so is anyone when the Secret has no certificate.
func TestAPreClaimSecretGoesOnlyToTheNameItsCertificateNames(t *testing.T) {
	sec := func(cert string) *corev1.Secret {
		if cert == "" {
			return secretWith(map[string]string{storage.StrategyAnnotation: "basic"})
		}
		return issuedTo(t, cert, map[string]string{storage.StrategyAnnotation: "basic"})
	}
	for _, tc := range []struct {
		name, user, cert string
		adopted          bool
	}{
		{"its dotted owner adopts it", "john.doe", "john.doe", true},
		{"the name that aliases it is refused", "johndoe", "john.doe", false},
		{"no certificate: no one adopts it", "john.doe", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := nameGuard{lookup: &fakeLookup{secret: sec(tc.cert)}, log: zerolog.Nop()}
			_, err := g.admit(context.Background(), storage.StrategyBasic, userAs(tc.user, "krateo-system", tc.user))
			if tc.adopted {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, RefusalHeldLegacy, RefusalOf(err), "the audit record's denial reason")
			st := status.FromError(err)
			assert.Equal(t, http.StatusForbidden, st.Code)
			assert.NotContains(t, st.Message, "certificate", "the answer stays opaque; the reason is private")
		})
	}
}
