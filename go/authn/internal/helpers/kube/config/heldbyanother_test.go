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
	assert.Empty(t, issued.Kubeconfig, "nothing is returned for the caller to use")
	assert.Contains(t, logs.String(), "username refused")
	logtest.NoIdentity(t, logs)
}
