package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/status"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/stretchr/testify/require"
)

// sentinelClaims is an ID token of a sentinel identity: every claim that
// names the person carries logtest.Marker.
func sentinelClaims(extra map[string]any) map[string]any {
	c := map[string]any{
		"sub": logtest.Subject, "preferred_username": logtest.User, "email": logtest.Email,
		"name": logtest.Marker + " Name", "picture": "https://x.example/" + logtest.Marker,
		"groups": []any{logtest.Marker + "-group"},
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// failingGenerator runs the issuance's admission checks, as the real
// generator does, and then answers err.
type failingGenerator struct {
	stepUpGenerator
	err error
}

func (g *failingGenerator) Generate(s storage.Strategy, u userinfo.Info, opts ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	if g.err == nil {
		return g.stepUpGenerator.Generate(s, u, opts...)
	}
	if err := kubeconfig.NewIssueOptions(opts...).CheckAdmit(u); err != nil {
		return kubeconfig.Issued{}, err
	}
	return kubeconfig.Issued{}, g.err
}

func (g *failingGenerator) GenerateStepUp(s storage.Strategy, u userinfo.Info, ttl time.Duration, opts ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	if g.err == nil {
		return g.stepUpGenerator.GenerateStepUp(s, u, ttl, opts...)
	}
	if err := kubeconfig.NewIssueOptions(opts...).CheckAdmit(u); err != nil {
		return kubeconfig.Issued{}, err
	}
	return kubeconfig.Issued{}, g.err
}

var (
	errGuardRefuses = kubeconfig.Refused(kubeconfig.RefusalClaimed,
		status.RefusedPrivately(status.CauseUsernameUnavailable, errors.New("the username isn't available to this identity"),
			errors.New("the username is claimed by another identity")))
	errIssuanceFails = errors.New("creating the credential Secret: Forbidden (403)")
)

// No log line of an OIDC login names the user, whether it succeeds, is
// refused or fails: not the ID token's sub, preferred_username, email, name
// or groups, nor a RESTAction's answer (Diego, 2026-11-12).
func TestOIDCLoginLogsNoIdentity(t *testing.T) {
	expired := float64(time.Now().Add(-time.Hour).Unix())
	cases := []struct {
		name   string
		spec   string
		claims map[string]any
		err    error
		code   int
	}{
		{name: "success", code: http.StatusOK},
		{name: "expired ID token", claims: map[string]any{"exp": expired}, code: http.StatusForbidden},
		{name: "not in allowedGroups", spec: `"allowedGroups":["admins"]`, code: http.StatusForbidden},
		{name: "name guard refuses", err: errGuardRefuses, code: http.StatusForbidden},
		{name: "issuance fails", err: errIssuanceFails, code: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := oidcEnv(t, tc.spec, sentinelClaims(tc.claims))
			gen := &failingGenerator{stepUpGenerator: stepUpGenerator{notAfter: time.Now().Add(time.Hour)}, err: tc.err}
			route := Login(t.Context(), rc, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: failureKey(t), JwtKeyID: "k"})

			req, logs := logtest.Request(httptest.NewRequest(http.MethodGet, Path+"?name=kc", nil))
			req.Header.Set("X-Auth-Code", "code")
			req.Header.Set("X-Code-Verifier", testCodeVerifier)
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			logtest.NoIdentity(t, logs)
		})
	}
}

// A RESTAction's answer completes the identity, so its values are the user's
// too: the login logs its keys, never its values, whether the answer is used
// or unusable.
func TestOIDCRESTActionLogsNoIdentity(t *testing.T) {
	for name, tc := range map[string]struct {
		answer string
		code   int
	}{
		"used": {fmt.Sprintf(`{"status":{"preferredUsername":%q,"email":%q,"name":"%s Name","groups":["%s-group"]}}`,
			logtest.User, logtest.Email, logtest.Marker, logtest.Marker), http.StatusOK},
		"unusable": {fmt.Sprintf(`{"status":{"preferredUsername":%q,"groups":"%s-group"}}`, logtest.User, logtest.Marker),
			http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			snowplow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.answer)
			}))
			t.Cleanup(snowplow.Close)
			rc := oidcEnv(t, `"restActionRef":{"name":"enrich","namespace":"krateo-system"}`, sentinelClaims(nil))
			base := xcontext.BuildContext(context.Background(), xcontext.WithAccessToken("authn-jwt"))
			base = context.WithValue(base, restaction.RestActionContextKey("snowplowURL"), snowplow.URL)
			gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
			route := Login(base, rc, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: failureKey(t), JwtKeyID: "k"})

			req, logs := logtest.Request(httptest.NewRequest(http.MethodGet, Path+"?name=kc", nil))
			req.Header.Set("X-Auth-Code", "code")
			req.Header.Set("X-Code-Verifier", testCodeVerifier)
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			logtest.NoIdentity(t, logs)
		})
	}
}

// No log line of an OIDC step-up names the user, whether it is granted,
// refused or fails.
func TestOIDCStepUpLogsNoIdentity(t *testing.T) {
	fresh := float64(time.Now().Add(-time.Minute).Unix())
	stale := float64(time.Now().Add(-time.Hour).Unix())
	cases := []struct {
		name   string
		stepUp string
		claims map[string]any
		err    error
		code   int
	}{
		{name: "granted", stepUp: stepUpGold, claims: map[string]any{"acr": "gold", "auth_time": fresh}, code: http.StatusOK},
		{name: "acr too low", stepUp: stepUpGold, claims: map[string]any{"acr": "silver", "auth_time": fresh}, code: http.StatusForbidden},
		{name: "stale authentication", stepUp: `{"acrValues":["gold"],"ttl":"20m","maxAge":"5m"}`,
			claims: map[string]any{"acr": "gold", "auth_time": stale}, code: http.StatusForbidden},
		{name: "step-up not enabled", claims: map[string]any{"acr": "gold", "auth_time": fresh}, code: http.StatusForbidden},
		{name: "misconfigured", stepUp: `{"acrValues":["gold"],"ttl":"5m"}`, claims: map[string]any{"acr": "gold", "auth_time": fresh},
			code: http.StatusInternalServerError},
		{name: "name guard refuses", stepUp: stepUpGold, claims: map[string]any{"acr": "gold", "auth_time": fresh},
			err: errGuardRefuses, code: http.StatusForbidden},
		{name: "issuance fails", stepUp: stepUpGold, claims: map[string]any{"acr": "gold", "auth_time": fresh},
			err: errIssuanceFails, code: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := stepUpEnv(t, tc.stepUp, sentinelClaims(tc.claims))
			gen := &failingGenerator{stepUpGenerator: stepUpGenerator{notAfter: time.Now().Add(15 * time.Minute)}, err: tc.err}
			route := StepUp(t.Context(), rc, StepUpOptions{KubeconfigGenerator: gen, JwtPrivateKey: failureKey(t), JwtKeyID: "k"})

			req, logs := logtest.Request(httptest.NewRequest(http.MethodPost, StepUpPath+"?name=kc", nil))
			req.Header.Set("X-Auth-Code", "code")
			req.Header.Set("X-Code-Verifier", testCodeVerifier)
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			logtest.NoIdentity(t, logs)
		})
	}
}
