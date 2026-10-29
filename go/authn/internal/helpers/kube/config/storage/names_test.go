package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A session Secret and a step-up Secret never share a name, whatever the two
// usernames are: otherwise one user's step-up would overwrite another user's
// session credential with an elevated certificate.
func TestStepUpSecretNameNeverCollidesWithASession(t *testing.T) {
	assert.Equal(t, "alice-clientconfig", ClientConfigSecretName("alice"))
	assert.Equal(t, "alice-clientconfig-stepup", StepUpSecretName("alice"))

	// The usernames an infix scheme would confuse.
	for _, pair := range [][2]string{
		{"bob", "bob-stepup"}, {"bob", "bob-clientconfig"}, {"bob-clientconfig", "bob"},
		{"bob", "bob-clientconfig-stepup"}, {"x.stepup", "x"},
	} {
		step, session := pair[0], pair[1]
		assert.NotEqual(t, StepUpSecretName(step), ClientConfigSecretName(session), "%s step-up vs %s session", step, session)
	}

	assert.False(t, strings.HasSuffix(StepUpSecretName("alice"), "-clientconfig"),
		"step-up Secrets are not listed as session credentials by suffix")
}
