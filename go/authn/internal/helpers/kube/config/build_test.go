package config

import (
	"errors"
	"github.com/krateo-platformops/authn/internal/status"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// An identity carrying a reserved group can only have been built around
// userinfo's guard. The generator refuses it before contacting the cluster.
func TestGenerateRefusesReservedGroups(t *testing.T) {
	gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"})
	user := &userinfo.DefaultUser{Name: "alice", ID: "1", Groups: []string{"devs", "krateo:loa:2"}}

	_, err := gen.Generate(storage.StrategyOIDC, user)
	require.ErrorContains(t, err, "krateo:loa: prefix, which is reserved to authn")
}

// A step-up credential exists to carry a krateo:loa: group. Without one, the
// caller didn't go through userinfo.NewStepUpUser, so it is refused.
func TestGenerateStepUpRequiresAReservedGroup(t *testing.T) {
	gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"})
	user := userinfo.NewDefaultUser("alice", "1", []string{"devs"}, nil)

	_, err := gen.GenerateStepUp(storage.StrategyOIDC, user, 15*time.Minute)
	require.ErrorContains(t, err, "must carry a krateo:loa: group")
}

// The verb an issuance would have sent comes from reading its Secret. When that
// read fails, the verb is left empty, so the audit record marks the gap, and is
// never guessed (AUDIT-4).
func TestTheWouldBeVerbIsNeverGuessed(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	for _, tc := range []struct {
		name   string
		lookup *fakeLookup
		want   string
	}{
		{"the Secret exists: update", &fakeLookup{secret: &corev1.Secret{}}, "update"},
		{"no Secret: create", &fakeLookup{}, "create"},
		{"the read fails: no verb", &fakeLookup{err: errors.New("apiserver unreachable")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"}, Lookup(tc.lookup)).(*kubeconfigGenerator)
			got := gen.wouldWrite("alice-clientconfig")
			assert.Equal(t, storage.Written{Namespace: "krateo-system", Name: "alice-clientconfig", Verb: tc.want}, got)
		})
	}
}

// An identity with no username names no Secret, at each of the two places that
// could invent one (authn#127, N21): secretFor never builds "-clientconfig",
// and wouldWrite never reports a verb for a Secret it can't name. wouldWrite
// keeps the namespace, so the name_missing record names the Secret resource
// without a name (audit v0.6.0).
func TestNoUsernameNamesNoSecret(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	nobody := &userinfo.DefaultUser{ID: "1"}
	assert.Empty(t, secretFor(nobody, storage.ClientConfigSecretName), "never a bare -clientconfig")
	assert.Empty(t, secretFor(nobody, storage.StepUpSecretName))
	assert.Equal(t, "alice-clientconfig", secretFor(&userinfo.DefaultUser{Name: "alice"}, storage.ClientConfigSecretName))

	gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"}, Lookup(&fakeLookup{})).(*kubeconfigGenerator)
	assert.Equal(t, storage.Written{Namespace: "krateo-system"}, gen.wouldWrite(""), "the namespace only: no name, no verb")
}

// An identity is refused for its own groups before any admission check
// (Admit) evaluates it (authn#133 review): a system: group, or a krateo: group
// from an identity source, is reported as such, never masked by a step-up's
// assurance refusal or an OIDCConfig's allowedGroups, on both issuance paths.
func TestGroupRefusalsComeBeforeAdmissionChecks(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	admits := map[string]IssueOption{
		"a step-up assurance refusal": Admit(func(userinfo.Info) error {
			return Refused(RefusalInsufficientAssurance, status.Refused("InsufficientAssurance", errors.New("acr too low")))
		}),
		"an allowedGroups refusal": Admit(func(userinfo.Info) error {
			return Refused(RefusalGroupNotAllowed, status.Refused("GroupNotAllowed", errors.New("not admitted")))
		}),
	}
	for _, id := range []struct {
		name string
		user userinfo.Info
		want Refusal
	}{
		{"a system: group", userAs("alice", "kc", "1", "devs", "system:masters"), RefusalSystemGroup},
		{"a krateo: group from an identity source", userAs("alice", "kc", "1", "devs", "krateo:admins"), RefusalPlatformGroup},
	} {
		for admitName, admit := range admits {
			gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"}, Lookup(&fakeLookup{})).(*kubeconfigGenerator)
			t.Run(id.name+" vs "+admitName+": login", func(t *testing.T) {
				_, err := gen.Generate(storage.StrategyOIDC, id.user, admit)
				assert.Equal(t, id.want, RefusalOf(err))
			})
			t.Run(id.name+" vs "+admitName+": step-up", func(t *testing.T) {
				up := userinfo.NewStepUpUser(id.user, 2) // as the step-up route builds it
				_, err := gen.GenerateStepUp(storage.StrategyOIDC, up, 15*time.Minute, admit)
				assert.Equal(t, id.want, RefusalOf(err))
			})
		}
	}
}

// A refused issuance's record names the Secret it would have written only
// when that name is the username's own (authn#138, legacy naming): the
// derivation lowercases, strips what an object name can't hold and truncates,
// so Alice@Example and alice:example would land on aliceexample-clientconfig,
// which can be a real user's Secret. Those, a dotted name, and a name the
// truncation cuts name the Secret resource without a name or a verb, as
// name_missing does; a well-formed name is named, a reserved one included.
func TestARefusalNamesOnlyTheUsernamesOwnSecret(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	refuse := Admit(func(userinfo.Info) error {
		return Refused(RefusalClaimed, status.Refused(status.CauseUsernameUnavailable, errors.New("claimed")))
	})
	long := strings.Repeat("a", 70) // past MakeDNS1123Compatible's 63
	for _, tc := range []struct {
		username string
		named    bool
	}{
		{"Alice@Example", false},
		{"alice:example", false},
		{"john.doe", false},
		{long, false},
		{"alice", true},
		{"admin", true}, // reserved, but well-formed: its refusals stay findable by its Secret
	} {
		t.Run(tc.username, func(t *testing.T) {
			gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"}, Lookup(&fakeLookup{})).(*kubeconfigGenerator)
			user := &userinfo.DefaultUser{Name: tc.username, ID: "1", Groups: []string{"devs"}}
			issued, err := gen.Generate(storage.StrategyLDAP, user, refuse)
			require.Error(t, err)
			require.Equal(t, RefusalClaimed, RefusalOf(err))
			if !tc.named {
				assert.Equal(t, storage.Written{Namespace: "krateo-system"}, issued.Secret,
					"the Secret resource only: no name, no verb")
				assert.Empty(t, gen.secretFor(user, true), "nor a step-up Secret")
				return
			}
			assert.Equal(t, storage.Written{Namespace: "krateo-system", Name: tc.username + "-clientconfig", Verb: "create"}, issued.Secret)
			assert.Equal(t, tc.username+"-clientconfig-stepup", gen.secretFor(user, true))
		})
	}
}

// Every issuance reports the verified identity's claim, whatever its outcome,
// so the sign-in's audit record says whose it was (audit v0.15.0): the value
// the name guard compares. An identity without a subject has none.
func TestIssuedCarriesTheVerifiedClaim(t *testing.T) {
	gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"})
	const iss = "https://kc.example/realms/krateo"
	want := storage.EncodeClaim(storage.StrategyOIDC, iss, "uid-alice")
	alice := func(groups ...string) *userinfo.DefaultUser {
		return &userinfo.DefaultUser{Name: "alice", ID: "1", Groups: groups, Subject: userinfo.Subject{Issuer: iss, ID: "uid-alice"}}
	}

	issued, err := gen.Generate(storage.StrategyOIDC, alice("devs", "krateo:loa:2"))
	require.Error(t, err, "refused for a reserved group")
	assert.Equal(t, want, issued.Claim)

	issued, err = gen.Generate(storage.StrategyOIDC, alice("system:masters"))
	require.Error(t, err, "refused for a system: group")
	assert.Equal(t, want, issued.Claim)

	issued, err = gen.GenerateStepUp(storage.StrategyOIDC, alice("devs"), 15*time.Minute)
	require.Error(t, err, "a step-up without its krateo:loa: group")
	assert.Equal(t, want, issued.Claim)

	issued, err = gen.Generate(storage.StrategyBasic, &userinfo.DefaultUser{Name: "bob", ID: "2", Subject: userinfo.Subject{ID: "bob"}})
	require.Error(t, err, "the unreachable cluster fails the issuance")
	assert.Equal(t, storage.EncodeClaim(storage.StrategyBasic, "", "bob"), issued.Claim, "a failure carries it too")

	issued, _ = gen.Generate(storage.StrategyOIDC, &userinfo.DefaultUser{Name: "carol", ID: "3"})
	assert.Empty(t, issued.Claim, "no subject, no claim")
}
