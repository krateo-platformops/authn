package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

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
			LogFailure(zerolog.New(&buf), tc.err).Str("name", "keycloak").Msg("login refused")

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
			assert.Equal(t, "keycloak", got["name"], "the caller can add its own fields")
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

// A private failure answers its public text with a 500 and logs the reason
// at error level.
func TestFailedPrivately(t *testing.T) {
	err := FailedPrivately("IssuanceFailed", errors.New("the identity provider's signing keys couldn't be read"),
		errors.New("GET https://kc.internal:8443/realms/krateo/certs: connection refused"))

	body, jerr := json.Marshal(FromError(err))
	require.NoError(t, jerr)
	assert.NotContains(t, string(body), "kc.internal", "the response doesn't carry the private reason")
	assert.Equal(t, 500, FromError(err).Code)

	var buf bytes.Buffer
	LogFailure(zerolog.New(&buf), err).Msg("delegation failed")
	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got), buf.String())
	assert.Equal(t, "error", got["level"])
	assert.Equal(t, "the identity provider's signing keys couldn't be read", got["error"])
	assert.Contains(t, got["reason"], "connection refused")
}

// RetryAfter is in whole seconds, rounded up, and only when set.
func TestRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want int
		ok   bool
	}{
		{in: 0, ok: false},
		{in: 300 * time.Millisecond, want: 1, ok: true},
		{in: 29*time.Second + time.Millisecond, want: 30, ok: true},
		{in: 30 * time.Second, want: 30, ok: true},
	} {
		got, ok := RetryAfter(fmt.Errorf("wrapped: %w", CauseError{Code: 503, Cause: "X", Err: errors.New("x"), RetryAfter: tc.in}))
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}
	_, ok := RetryAfter(errors.New("plain"))
	assert.False(t, ok)
}

// Answered text reaches the caller, never the log.
func TestAnsweredIsNeverLogged(t *testing.T) {
	err := CauseError{Code: http.StatusForbidden, Cause: "TokenNotAuthenticated",
		Err: errors.New("token not authenticated"), Answered: `serviceaccounts "zz-sentinel-user" not found`}

	st := FromError(err)
	assert.Equal(t, `token not authenticated: serviceaccounts "zz-sentinel-user" not found`, st.Message)
	assert.Equal(t, st.Message, st.Details.Causes[0].Message)

	var buf bytes.Buffer
	LogFailure(zerolog.New(&buf), err).Msg("login refused")
	assert.Contains(t, buf.String(), "token not authenticated")
	assert.NotContains(t, buf.String(), "zz-sentinel-user")
}
