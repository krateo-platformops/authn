package oidc

import (
	"net/http"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The identity issued is named by the ID token's iss and sub, which no
// RESTAction or UserInfo answer can change. A step-up credential names the
// same identity as the session it raises.
func TestLoginNamesTheIDTokensSubject(t *testing.T) {
	want := userinfo.Subject{Issuer: testIssuer, ID: "idp-user-1"}

	gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
	rec := loginRequest(t, oidcEnv(t, "", map[string]any{}), gen)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, gen.sessions, 1)
	assert.Equal(t, want, gen.sessions[0].GetSubject())

	rc := stepUpEnv(t, stepUpGold, map[string]any{"acr": "gold", "auth_time": float64(time.Now().Add(-time.Minute).Unix())})
	gen = &stepUpGenerator{notAfter: time.Now().Add(12 * time.Minute)}
	rec = stepUpRequest(t, rc, gen)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, gen.stepUps, 1)
	assert.Equal(t, want, gen.stepUps[0].GetSubject())
}

// sub is required (OIDC Core 2): an ID token without it names no one, so the
// login is refused as an invalid ID token and nothing is issued.
func TestLoginRefusesAnIDTokenWithoutSub(t *testing.T) {
	for name, sub := range map[string]any{"absent": nil, "empty": "", "not a string": 42.0} {
		t.Run(name, func(t *testing.T) {
			gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
			rec := loginRequest(t, oidcEnv(t, "", map[string]any{"sub": sub}), gen)
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), `"reason":"IDTokenInvalid"`)
			assert.Empty(t, gen.sessions)
		})
	}
}
