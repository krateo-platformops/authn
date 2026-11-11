package config

import (
	"errors"
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
	require.ErrorContains(t, err, `group "krateo:loa:2" is reserved`)
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
