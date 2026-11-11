package oidc

import (
	"encoding/json"
	"errors"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

func TestCheckAllowedGroups(t *testing.T) {
	user := func(groups ...string) userinfo.Info {
		return userinfo.NewDefaultUser("alice", "uid", groups, nil)
	}

	assert.NoError(t, checkAllowedGroups(nil, user()), "no allowedGroups admits everyone")
	assert.NoError(t, checkAllowedGroups([]string{}, user("devs")), "an empty list admits everyone")
	assert.NoError(t, checkAllowedGroups([]string{"child:acme:member"}, user("devs", "child:acme:member")))
	assert.NoError(t, checkAllowedGroups([]string{"ops", "devs"}, user("devs")), "any one allowed group is enough")

	for name, nfo := range map[string]userinfo.Info{
		"no groups":     user(),
		"other groups":  user("devs", "child:globex:member"),
		"case differs":  user("Child:Acme:Member"),
		"reserved only": user("krateo:loa:2"), // stripped by NewDefaultUser: can never admit
	} {
		err := checkAllowedGroups([]string{"child:acme:member", "krateo:loa:2"}, nfo)
		var ce status.CauseError
		require.True(t, errors.As(err, &ce), "%s: want a CauseError, got %v", name, err)
		assert.Equal(t, http.StatusForbidden, ce.Code, name)
		assert.Equal(t, CauseGroupNotAllowed, ce.Cause, name)
	}
}

func loginRequest(t *testing.T, rc *rest.Config, gen *stepUpGenerator) *httptest.ResponseRecorder {
	t.Helper()
	audit, records := auditlogtest.New(t)
	gen.records = records
	route := Login(t.Context(), rc, LoginOptions{KubeconfigGenerator: gen, Audit: audit, JwtDuration: time.Hour, JwtPrivateKey: failureKey(t), JwtKeyID: "k"})

	req := httptest.NewRequest(http.MethodGet, Path+"?name=kc", nil)
	req.Header.Set("X-Auth-Code", "code")
	req.Header.Set("X-Code-Verifier", testCodeVerifier)
	rec := httptest.NewRecorder()
	auditlog.Middleware(route.Handler()).ServeHTTP(rec, req)
	return rec
}

func causeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Details struct {
			Causes []struct {
				Reason string `json:"reason"`
			} `json:"causes"`
		} `json:"details"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	require.Len(t, out.Details.Causes, 1)
	return out.Details.Causes[0].Reason
}

// The ID token's groups are [devs] (the fake IdP also asserts krateo:loa:2,
// which authn strips). A login is admitted only when allowedGroups names one
// of the user's groups, and a refused login mints nothing.
func TestLoginHonoursAllowedGroups(t *testing.T) {
	fresh := map[string]any{"acr": "gold", "auth_time": float64(time.Now().Add(-time.Minute).Unix())}

	t.Run("admitted", func(t *testing.T) {
		gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
		rec := loginRequest(t, oidcEnv(t, `"allowedGroups":["ops","devs"]`, fresh), gen)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Len(t, gen.sessions, 1)
		r := auditlogtest.Only(t, gen.records)
		assert.Equal(t, "authn.login.oidc", auditlogtest.String(r, "krateo.action"))
		assert.Equal(t, "success", auditlogtest.String(r, "krateo.audit.outcome"))
		assert.Equal(t, "/oidc/login?name=kc", auditlogtest.String(r, "krateo.request.uri"), "a callback keeps name, never code or state")
	})

	t.Run("not a member", func(t *testing.T) {
		gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
		rec := loginRequest(t, oidcEnv(t, `"allowedGroups":["child:acme:member"]`, fresh), gen)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, "GroupNotAllowed", causeOf(t, rec))
		assert.Empty(t, gen.sessions, "nothing is minted for a refused user")
		assert.NotContains(t, rec.Body.String(), "accessToken")
		// A verified identity refused: a denied record (AUDIT-4).
		r := auditlogtest.Only(t, gen.records)
		assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
	})

	t.Run("the reserved group the IdP asserted never admits", func(t *testing.T) {
		gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
		rec := loginRequest(t, oidcEnv(t, `"allowedGroups":["krateo:loa:2"]`, fresh), gen)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, "GroupNotAllowed", causeOf(t, rec))
		assert.Empty(t, gen.sessions)
	})

	t.Run("step-up is gated too", func(t *testing.T) {
		gen := &stepUpGenerator{notAfter: time.Now().Add(15 * time.Minute)}
		rec := stepUpRequest(t, oidcEnv(t, `"allowedGroups":["child:acme:member"],"stepUp":`+stepUpGold, fresh), gen)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, "GroupNotAllowed", causeOf(t, rec))
		assert.Empty(t, gen.stepUps)
		r := auditlogtest.Only(t, gen.records)
		assert.Equal(t, "authn.stepup.oidc", auditlogtest.String(r, "krateo.action"))
		assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
		assert.Equal(t, "alice-clientconfig-stepup", auditlogtest.String(r, "krateo.audit.object_ref.name"))
	})
}
