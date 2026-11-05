package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A claim of the wrong type is a malformed ID token: 403 IDTokenInvalid,
// answered as a Status, nothing minted. It used to panic the request, which
// dropped the connection with no answer at all.
func TestWronglyTypedClaimsAreRefused(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"groups a string":       {"groups": "devs"},
		"groups with a number":  {"groups": []any{"devs", 7}},
		"name a number":         {"name": 42},
		"email a bool":          {"email": true},
		"preferred_username {}": {"preferred_username": map[string]any{"x": "y"}},
		"picture a list":        {"picture": []any{"p"}},
		"acr a number":          {"acr": 2},
		"auth_time a string":    {"auth_time": "yesterday"},
	} {
		t.Run(name, func(t *testing.T) {
			gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
			rec := loginRequest(t, oidcEnv(t, "", claims), gen)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, "IDTokenInvalid", causeOf(t, rec))
			assert.Empty(t, gen.sessions, "nothing minted")
		})
	}
}

// A null claim is an omitted one (OIDC Core §5.1 asks providers to omit
// rather than send null): the login goes on, asking UserInfo when there is one.
func TestNullClaimsAreOmitted(t *testing.T) {
	gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
	rec := loginRequest(t, oidcEnv(t, "", map[string]any{"name": nil, "groups": nil, "acr": nil, "auth_time": nil}), gen)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, gen.sessions, 1)
	assert.Equal(t, "alice", gen.sessions[0].GetUserName())
	assert.Empty(t, gen.sessions[0].GetGroups())
}

// A session says which login issued it, in /strategies' terms, so a client can
// find the entry and offer that entry's step-up.
func TestLoginNamesItsStrategy(t *testing.T) {
	gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
	rec := loginRequest(t, oidcEnv(t, "", map[string]any{}), gen)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"strategy":{"kind":"oidc","name":"kc"}`)
}

// UserInfo is asked only for the profile claims the ID token omits; what it
// answers is checked the same way, and a bad answer is authn's IdP failing:
// 500 UserInfoFailed.
func TestUserInfoAnswers(t *testing.T) {
	userInfo := func(code int, body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer at", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return `"userInfoURL":"` + srv.URL + `"`
	}
	omitEmail := map[string]any{"email": nil}

	t.Run("fills the omitted claim", func(t *testing.T) {
		gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
		rec := loginRequest(t, oidcEnv(t, userInfo(200, `{"email":"alice@idp.example","name":"Not Used"}`), omitEmail), gen)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Len(t, gen.sessions, 1)
		exts := gen.sessions[0].GetExtensions()
		assert.Equal(t, "alice@idp.example", exts.Get("email"))
		assert.Equal(t, "Alice", exts.Get("name"), "a claim the ID token has is never taken from UserInfo")
	})

	for name, tc := range map[string]struct {
		code int
		body string
	}{
		"a wrongly typed field": {200, `{"email":42}`},
		"a refusal":             {401, `{"error":"invalid_token"}`},
		"not JSON":              {200, `<html>`},
	} {
		t.Run(name, func(t *testing.T) {
			gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
			rec := loginRequest(t, oidcEnv(t, userInfo(tc.code, tc.body), omitEmail), gen)
			require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
			assert.Equal(t, "UserInfoFailed", causeOf(t, rec))
			assert.Empty(t, gen.sessions, "nothing minted")
		})
	}
}
