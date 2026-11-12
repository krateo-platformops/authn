package config

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The names the Secret-name derivation rewrites (lowercase, [-a-z0-9], at
// most 63), and some it leaves alone.
var (
	rewrittenNames = []string{"Alice.Smith", "alice.smith", "ALICE", "alice_smith", "alice@corp", "-alice", strings.Repeat("a", 64)}
	issuedNames    = []string{"alice", "alice-smith", "a1", strings.Repeat("a", 63)}
)

// An identity source's name the derivation would rewrite is refused,
// name_not_issued, before the guard reads anything: its certificate would
// carry one name and its Secret, and the tenant generated from it, another
// (Diego, 2026-11-12). LDAP issues the entry's uid as is, so this is where it
// fires; OAuth and OIDC normalize first, and are held to the same rule.
func TestAnIdentitySourceNameAuthnWouldRewriteIsRefused(t *testing.T) {
	for _, strategy := range []storage.Strategy{storage.StrategyLDAP, storage.StrategyOAuth, storage.StrategyOIDC} {
		for _, name := range rewrittenNames {
			l := &fakeLookup{}
			g := nameGuard{lookup: l, log: zerolog.Nop()}
			_, err := g.admit(context.Background(), strategy, userAs(name, "src", "id-1"))
			require.Error(t, err, "%s %q", strategy, name)
			assert.Equal(t, RefusalNotIssued, RefusalOf(err), "%s %q", strategy, name)
			st := status.FromError(err)
			assert.Equal(t, http.StatusForbidden, st.Code)
			assert.Equal(t, status.CauseUsernameUnavailable, st.Details.Causes[0].Type, "the same answer as every name refusal")
			assert.Empty(t, l.asked, "%s %q: refused before any read", strategy, name)
		}
		for _, name := range issuedNames {
			g := nameGuard{lookup: &fakeLookup{}, log: zerolog.Nop()}
			_, err := g.admit(context.Background(), strategy, userAs(name, "src", "id-1"))
			assert.NoError(t, err, "%s %q is in the form authn issues", strategy, name)
		}
	}
}

// An administrator-provisioned name is not held to it: a basic User or a
// ServiceAccount mapping signs in as it always has, dots and length included
// (057's basic Users with dotted names, demo's 65-character controller mapping).
func TestAProvisionedNameIsNotHeldToTheIssuedForm(t *testing.T) {
	for _, strategy := range []storage.Strategy{storage.StrategyBasic, storage.StrategyServiceAccount} {
		for _, name := range rewrittenNames {
			g := nameGuard{lookup: &fakeLookup{}, log: zerolog.Nop()}
			_, err := g.admit(context.Background(), strategy, userAs(name, "src", "id-1"))
			assert.NoError(t, err, "%s %q", strategy, name)
		}
	}
}

// A refusal's record names the Secret only when the derivation leaves the
// username unchanged: a rewritten name's Secret isn't its own and may be
// another user's (authn#138). It still names authn's namespace.
func TestARefusalNamesTheSecretOnlyWhenItIsTheNamesOwn(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	// A system: group is refused before the guard, whatever the strategy, so
	// a provisioned name with dots is refused too, and its record is checked.
	rewritten := map[string]bool{}
	for _, n := range rewrittenNames {
		rewritten[n] = true
	}
	for _, name := range append(append([]string{}, rewrittenNames...), issuedNames...) {
		gen := &kubeconfigGenerator{lookup: &fakeLookup{}, log: zerolog.Nop()}
		issued, err := gen.Generate(storage.StrategyBasic, userAs(name, "src", "id-1", "system:masters"))
		require.Error(t, err)
		assert.Equal(t, "krateo-system", issued.Secret.Namespace, "%q", name)
		if rewritten[name] {
			assert.Empty(t, issued.Secret.Name, "%q: the derived Secret isn't the name's own", name)
			assert.Empty(t, issued.Secret.Verb, "%q: no named Secret, no verb", name)
		} else {
			assert.Equal(t, storage.ClientConfigSecretName(name), issued.Secret.Name, "%q", name)
		}
	}
	// The identity-source refusal itself names none either.
	gen := &kubeconfigGenerator{lookup: &fakeLookup{}, log: zerolog.Nop()}
	issued, err := gen.Generate(storage.StrategyLDAP, userAs("Alice.Smith", "src", "uid=alice"))
	require.Equal(t, RefusalNotIssued, RefusalOf(err))
	assert.Empty(t, issued.Secret.Name)
}

// OIDC step-up holds its identity to the same form, and logs no identity
// refusing it.
func TestAStepUpForANameAuthnWouldRewriteIsRefused(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	logs, l := logtest.Capture()
	gen := generator(t, storage.StepUpSecretName(logtest.LongUser), secretReplies{}, nil, l)
	_, err := gen.GenerateStepUp(storage.StrategyOIDC, userinfo.NewStepUpUser(sentinelUser(logtest.LongUser), 2), 15*time.Minute)
	require.Error(t, err)
	assert.Equal(t, RefusalNotIssued, RefusalOf(err))
	logFailure(l, err)
	require.Contains(t, logs.String(), "name_not_issued")
	logtest.NoIdentity(t, logs)
}
