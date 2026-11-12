package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With exact names on, authn refuses to start when its own identity can't
// name its Secret exactly, or when plumbing's signup would write that Secret
// under another (legacy) name. Off, any AUTHN_USERNAME runs, as before.
func TestSessionNamingRefusesAnAuthnUsernameItCantIssue(t *testing.T) {
	for _, self := range []string{"authn", "authn-dev", "krateo-authn"} {
		n, err := sessionNaming(true, self)
		require.NoError(t, err, self)
		assert.True(t, n.Exact)
	}
	for _, self := range []string{"Authn", "authn_svc", "authn.svc", strings.Repeat("a", 64), strings.Repeat("a", 234), ""} {
		_, err := sessionNaming(true, self)
		require.Error(t, err, "%q", self)
		assert.Contains(t, err.Error(), "AUTHN_EXACT_USERNAMES is on")
		n, err := sessionNaming(false, self)
		require.NoError(t, err, "%q: off, nothing is checked", self)
		assert.False(t, n.Exact)
	}
}
