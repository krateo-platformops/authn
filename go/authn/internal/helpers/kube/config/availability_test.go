package config

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// stepLookup answers each lookup separately, and can fail one of them.
type stepLookup struct {
	secret      *corev1.Secret
	provisioned bool
	bound       bool
	failAt      string // "secret", "provisioned" or "bound"
	asked       []string
}

func (s *stepLookup) fail(step string) error {
	s.asked = append(s.asked, step)
	if s.failAt == step {
		return errors.New("apiserver down")
	}
	return nil
}
func (s *stepLookup) SessionSecret(context.Context, string) (*corev1.Secret, error) {
	return s.secret, s.fail("secret")
}
func (s *stepLookup) Secret(context.Context, string) (*corev1.Secret, error) { return s.secret, nil }
func (s *stepLookup) Provisioned(context.Context, string) (bool, error) {
	return s.provisioned, s.fail("provisioned")
}
func (s *stepLookup) BoundAsUser(context.Context, string) (bool, error) {
	return s.bound, s.fail("bound")
}

// Each reason in the guard's order, and the name only available when nothing
// holds it (POST /usernames/check).
func TestCheckUsername(t *testing.T) {
	claimed := secretWith(map[string]string{storage.ClaimAnnotation: storage.EncodeClaim(storage.StrategyOIDC, "kc", "9")})
	legacyOIDC := secretWith(map[string]string{storage.StrategyAnnotation: string(storage.StrategyOIDC)})
	for _, tc := range []struct {
		name   string
		user   string
		lookup stepLookup
		want   Unavailable
		asked  []string
	}{
		{name: "available", user: "alice", want: "", asked: []string{"secret", "provisioned", "bound"}},
		{name: "empty", user: "", want: UnavailableInvalid},
		{name: "too long", user: strings.Repeat("a", 64), want: UnavailableInvalid},
		{name: "not in the issued form", user: "Alice@Example", want: UnavailableInvalid},
		{name: "reserved", user: "admin", want: UnavailableReserved},
		{name: "a reserved prefix", user: "system:alice", want: UnavailableReserved},
		{name: "the platform's prefix", user: "krateo:public", want: UnavailableReserved},
		{name: "a claimed Secret", user: "alice", lookup: stepLookup{secret: claimed}, want: UnavailableClaimed, asked: []string{"secret"}},
		{name: "a pre-claims Secret", user: "alice", lookup: stepLookup{secret: secretWith(nil)}, want: UnavailableHeldLegacy, asked: []string{"secret"}},
		// A sign-in by the strategy that wrote it would adopt this one; a new
		// person must not get it.
		{name: "a pre-claims Secret its own strategy would adopt", user: "alice", lookup: stepLookup{secret: legacyOIDC}, want: UnavailableHeldLegacy},
		{name: "provisioned", user: "alice", lookup: stepLookup{provisioned: true}, want: UnavailableProvisioned, asked: []string{"secret", "provisioned"}},
		{name: "bound", user: "alice", lookup: stepLookup{bound: true}, want: UnavailableBound, asked: []string{"secret", "provisioned", "bound"}},
		// The guard's order: a Secret is reported before a provisioned
		// identity or a binding.
		{name: "Secret and bound: the Secret first", user: "alice", lookup: stepLookup{secret: claimed, bound: true, provisioned: true}, want: UnavailableClaimed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckUsername(context.Background(), &tc.lookup, tc.user)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			if tc.asked != nil {
				assert.Equal(t, tc.asked, tc.lookup.asked, "reads only what it needs, in order")
			}
			if tc.want == UnavailableInvalid || tc.want == UnavailableReserved {
				assert.Empty(t, tc.lookup.asked, "a name authn never issues needs no cluster read")
			}
		})
	}
}

// A lookup that fails is an error, never a verdict: the caller treats the
// name as unavailable and retries (fail closed).
func TestCheckUsernameFailsClosed(t *testing.T) {
	for _, step := range []string{"secret", "provisioned", "bound"} {
		t.Run(step, func(t *testing.T) {
			got, err := CheckUsername(context.Background(), &stepLookup{failAt: step}, "alice")
			require.Error(t, err)
			assert.Empty(t, got)
		})
	}
	_, err := CheckUsername(context.Background(), nil, "alice")
	require.Error(t, err, "no lookup is a failure, not available")
}

func TestUnavailablesListsEveryReason(t *testing.T) {
	assert.ElementsMatch(t, []Unavailable{"invalid", "reserved", "name_claimed", "name_held_legacy", "name_provisioned", "name_bound"}, Unavailables)
}
