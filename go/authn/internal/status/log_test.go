package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refusal of the caller is logged at warn, authn's own failure at error,
// each with the error, the code it was answered with and its cause.
func TestLogFailure(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		level string
		code  int
		cause string
	}{
		{name: "401", err: CauseError{Code: http.StatusUnauthorized, Cause: "MissingBearer", Err: errors.New("no bearer")},
			level: "warn", code: 401, cause: "MissingBearer"},
		{name: "403", err: Refused("NoMapping", errors.New("no mapping")),
			level: "warn", code: 403, cause: "NoMapping"},
		{name: "403 wrapped", err: fmt.Errorf("login: %w", Refused("NoMapping", errors.New("no mapping"))),
			level: "warn", code: 403, cause: "NoMapping"},
		{name: "500", err: Failed(CauseIssuanceFailed, errors.New("csr not approved")),
			level: "error", code: 500, cause: "IssuanceFailed"},
		{name: "no cause", err: errors.New("boom"),
			level: "error", code: 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			LogFailure(zerolog.New(&buf), tc.err).Str("username", "alice").Msg("login refused")

			var got map[string]any
			require.NoError(t, json.Unmarshal(buf.Bytes(), &got), buf.String())
			assert.Equal(t, tc.level, got["level"])
			assert.Equal(t, tc.err.Error(), got["error"])
			assert.Equal(t, float64(tc.code), got["code"])
			if tc.cause == "" {
				assert.NotContains(t, got, "cause")
			} else {
				assert.Equal(t, tc.cause, got["cause"])
			}
			assert.Equal(t, "alice", got["username"], "the caller can add its own fields")
			assert.Equal(t, "login refused", got["message"])
			assert.NotContains(t, got, "reason", "no private reason was given")
		})
	}
}

// A private reason is logged, never answered.
func TestRefusedPrivately(t *testing.T) {
	err := RefusedPrivately("InvalidCredentials", errors.New("invalid credentials"), errors.New(`users "bob" not found`))

	body, jerr := json.Marshal(FromError(err))
	require.NoError(t, jerr)
	assert.NotContains(t, string(body), "bob", "the response doesn't carry the private reason")
	assert.Equal(t, 403, FromError(err).Code)

	var buf bytes.Buffer
	LogFailure(zerolog.New(&buf), err).Msg("login refused")
	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got), buf.String())
	assert.Equal(t, "warn", got["level"])
	assert.Equal(t, "invalid credentials", got["error"])
	assert.Equal(t, `users "bob" not found`, got["reason"])
}
