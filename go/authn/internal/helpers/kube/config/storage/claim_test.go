package storage

import (
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// Two claims are the same identity exactly when their strings are equal,
// whatever the parts contain: an issuer and an ID can't be shifted into each
// other.
func TestEncodeClaimKeepsThePartsApart(t *testing.T) {
	assert.Equal(t, `["oidc","https://kc/realms/x","1"]`, EncodeClaim(StrategyOIDC, "https://kc/realms/x", "1"))
	assert.NotEqual(t, EncodeClaim(StrategyOIDC, "a:b", "c"), EncodeClaim(StrategyOIDC, "a", "b:c"))
	assert.NotEqual(t, EncodeClaim(StrategyLDAP, `corp","x`, "y"), EncodeClaim(StrategyLDAP, "corp", `x","y`))
}

// The claim is written on the session Secret, on create and on the update of
// an existing one, next to the strategy and groups.
func TestPutWritesTheClaim(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	claim := EncodeClaim(StrategyOAuth, "gh", "1001")
	for _, exists := range []bool{false, true} {
		rec := &putRecorder{exists: exists}
		store := Default(&rest.Config{Host: rec.serve(t).URL})
		require.NoError(t, store.Put("alice", &AuthInfo{Strategy: StrategyOAuth, Claim: claim,
			CertData: identityCert(t, "alice", []string{"tenants"})}))
		require.NotEmpty(t, rec.written)
		for _, sec := range rec.written {
			assert.Equal(t, claim, sec.Annotations[ClaimAnnotation], "exists=%v", exists)
			assert.Equal(t, "oauth", sec.Annotations[StrategyAnnotation])
		}
	}
}

// An existing Secret claimed by another identity is never overwritten: the
// write is refused with ErrClaimedByAnother, and nothing is stored. A Secret
// with no claim, or with the same one, is updated.
func TestPutRefusesASecretClaimedByAnother(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := EncodeClaim(StrategyOAuth, "gh", "1001")
	theirs := EncodeClaim(StrategyOAuth, "gh", "6666")
	nfo := func() *AuthInfo {
		return &AuthInfo{Strategy: StrategyOAuth, Claim: mine, CertData: identityCert(t, "alice", []string{"tenants"})}
	}

	rec := &putRecorder{exists: true, existing: map[string]string{ClaimAnnotation: theirs}}
	err := Default(&rest.Config{Host: rec.serve(t).URL}).Put("alice", nfo())
	require.ErrorIs(t, err, ErrClaimedByAnother)
	require.Len(t, rec.written, 1, "only the create that found the Secret; no update")

	for _, existing := range []map[string]string{nil, {ClaimAnnotation: mine}, {StrategyAnnotation: "oauth"}} {
		rec := &putRecorder{exists: true, existing: existing}
		require.NoError(t, Default(&rest.Config{Host: rec.serve(t).URL}).Put("alice", nfo()))
		assert.Len(t, rec.written, 2, "the create, then the update")
	}
}
