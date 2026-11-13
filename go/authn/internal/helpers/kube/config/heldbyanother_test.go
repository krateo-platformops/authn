package config

import (
	"net/http"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An unclaimed Secret that appears under the name between the guard's read
// and the write, holding no certificate this username owns, is never
// replaced: the write is refused as the guard would refuse it,
// name_held_legacy, 403 UsernameUnavailable, and nothing is returned.
func TestAWriteOverAnUnclaimedSecretItDoesntOwnIsRefused(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	logs, l := logtest.Capture()
	gen := generator(t, storage.ClientConfigSecretName(logtest.User),
		secretReplies{create: http.StatusConflict, update: http.StatusOK}, nil, l)
	issued, err := gen.Generate(storage.StrategyOIDC, sentinelUser(logtest.User))
	require.Error(t, err)
	assert.Equal(t, RefusalHeldLegacy, RefusalOf(err))
	st := status.FromError(err)
	assert.Equal(t, http.StatusForbidden, st.Code)
	assert.Equal(t, status.CauseUsernameUnavailable, st.Details.Causes[0].Type)
	assert.NotContains(t, st.Message, "certificate", "the answer stays opaque; the reason is private")
	assert.Empty(t, issued.Kubeconfig, "nothing is returned for the caller to use")
	assert.Contains(t, logs.String(), "username refused")
	logtest.NoIdentity(t, logs)
}

// A refusal at the write names the Secret only when it is the username's own
// (authn#138): john.doe's derived name is johndoe-clientconfig, which may be
// johndoe's, so a write refused there (claimed by another identity) names the
// Secret resource without a name or a verb, though Put read it. A well-formed
// name refused the same way names its Secret and the update it would have
// sent.
func TestARefusalAtTheWriteNamesOnlyTheUsernamesOwnSecret(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	theirs := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Marker+"-other")
	for _, tc := range []struct {
		username string
		want     storage.Written
	}{
		{"john.doe", storage.Written{Namespace: "krateo-system"}},
		{logtest.User, storage.Written{Namespace: "krateo-system", Name: storage.ClientConfigSecretName(logtest.User), Verb: "update"}},
	} {
		t.Run(tc.username, func(t *testing.T) {
			_, l := logtest.Capture()
			gen := generator(t, storage.ClientConfigSecretName(tc.username),
				secretReplies{create: http.StatusConflict, claim: theirs}, nil, l)
			issued, err := gen.Generate(storage.StrategyOIDC, sentinelUser(tc.username))
			require.Error(t, err)
			require.Equal(t, RefusalClaimed, RefusalOf(err), "refused at the write, not by the guard")
			assert.Equal(t, tc.want, issued.Secret)
		})
	}
}
