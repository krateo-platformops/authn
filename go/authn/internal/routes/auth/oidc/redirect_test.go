package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The IdP's endpoints are called with credentials (client secret, code and
// verifier in the token request; the user's token at UserInfo), so a redirect
// from any of them is refused: the login fails with that call's cause and the
// redirect target never hears from authn.
func TestIdPRedirectsAreRefused(t *testing.T) {
	reached := 0
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++ }))
	t.Cleanup(dest.Close)
	redirect := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL+"/steal", code) }
	}
	redirector := func(code int) string {
		srv := httptest.NewServer(redirect(code))
		t.Cleanup(srv.Close)
		return srv.URL
	}

	t.Run("token endpoint", func(t *testing.T) {
		reached = 0
		rc, _ := failureEnv(t, "", nil, redirect(http.StatusTemporaryRedirect))
		rec, gen := answer(t, rc, false, "?name=kc", "c")
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		assert.Equal(t, "TokenExchangeFailed", decodeStatus(t, rec).Details.Causes[0].Reason)
		assert.Empty(t, gen.sessions)
		assert.Zero(t, reached, "the client secret, code and verifier never left for the redirect target")
	})

	t.Run("discovery", func(t *testing.T) {
		reached = 0
		rc, _ := failureEnv(t, `"discoveryURL":"`+redirector(http.StatusFound)+`"`, nil, tokenAnswer(http.StatusOK, `{}`))
		rec, _ := answer(t, rc, false, "?name=kc", "c")
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		assert.Equal(t, "OIDCDiscoveryFailed", decodeStatus(t, rec).Details.Causes[0].Reason)
		assert.Zero(t, reached)
	})

	t.Run("userinfo", func(t *testing.T) {
		reached = 0
		gen := &stepUpGenerator{}
		rec := loginRequest(t, oidcEnv(t, `"userInfoURL":"`+redirector(http.StatusTemporaryRedirect)+`"`, map[string]any{"email": nil}), gen)
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		assert.Equal(t, "UserInfoFailed", causeOf(t, rec))
		assert.Empty(t, gen.sessions)
		assert.Zero(t, reached, "the user's token never left for the redirect target")
	})
}
