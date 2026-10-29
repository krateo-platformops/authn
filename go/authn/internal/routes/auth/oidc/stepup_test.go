package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	oidcv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oidc/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestResolveStepUp(t *testing.T) {
	assert.Nil(t, resolveStepUp(nil), "no spec.stepUp, no step-up")

	cfg := resolveStepUp(&oidcv1alpha1.OIDCStepUp{AcrValues: []string{"gold"}})
	assert.Equal(t, &stepUpConfig{acrValues: []string{"gold"}, maxAge: 5 * time.Minute, ttl: 15 * time.Minute}, cfg)

	cfg = resolveStepUp(&oidcv1alpha1.OIDCStepUp{AcrValues: []string{"gold"},
		MaxAge: &metav1.Duration{Duration: time.Minute}, TTL: &metav1.Duration{Duration: 30 * time.Minute}})
	assert.Equal(t, time.Minute, cfg.maxAge)
	assert.Equal(t, 30*time.Minute, cfg.ttl)
}

func TestCheckStepUp(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	enabled := &stepUpConfig{acrValues: []string{"gold", "urn:krateo:loa:2"}, maxAge: 5 * time.Minute, ttl: 15 * time.Minute}
	fresh := idToken{acr: "gold", authTime: now.Add(-time.Minute)}

	cases := []struct {
		name  string
		cfg   *stepUpConfig
		tok   idToken
		code  int
		cause status.CauseType
	}{
		{name: "granted", cfg: enabled, tok: fresh},
		{name: "second acr value", cfg: enabled, tok: idToken{acr: "urn:krateo:loa:2", authTime: now}},
		{name: "authenticated exactly maxAge ago", cfg: enabled, tok: idToken{acr: "gold", authTime: now.Add(-5 * time.Minute)}},

		{name: "not enabled", cfg: nil, tok: fresh, code: 403, cause: CauseStepUpNotEnabled},
		{name: "acr too low", cfg: enabled, tok: idToken{acr: "silver", authTime: now}, code: 403, cause: CauseInsufficientAssurance},
		{name: "no acr", cfg: enabled, tok: idToken{authTime: now}, code: 403, cause: CauseInsufficientAssurance},
		{name: "no auth_time", cfg: enabled, tok: idToken{acr: "gold"}, code: 403, cause: CauseStaleAuthentication},
		{name: "old SSO session at the right level", cfg: enabled, tok: idToken{acr: "gold", authTime: now.Add(-time.Hour)},
			code: 403, cause: CauseStaleAuthentication},
		{name: "ttl below the CSR minimum", tok: fresh, code: 500, cause: CauseStepUpMisconfigured,
			cfg: &stepUpConfig{acrValues: []string{"gold"}, maxAge: time.Minute, ttl: 5 * time.Minute}},
		{name: "no acr values", tok: fresh, code: 500, cause: CauseStepUpMisconfigured,
			cfg: &stepUpConfig{maxAge: time.Minute, ttl: 15 * time.Minute}},
		{name: "zero maxAge", tok: fresh, code: 500, cause: CauseStepUpMisconfigured,
			cfg: &stepUpConfig{acrValues: []string{"gold"}, ttl: 15 * time.Minute}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStepUp(tc.cfg, tc.tok, now)
			if tc.cause == "" {
				require.NoError(t, err)
				return
			}
			var ce status.CauseError
			require.True(t, errors.As(err, &ce), "want a CauseError, got %v", err)
			assert.Equal(t, tc.code, ce.Code)
			assert.Equal(t, tc.cause, ce.Cause)
		})
	}
}

// stepUpGenerator records what the handler asks the generator to mint.
type stepUpGenerator struct {
	sessions []userinfo.Info
	stepUps  []userinfo.Info
	ttls     []time.Duration
	notAfter time.Time
}

func (g *stepUpGenerator) Generate(_ storage.Strategy, u userinfo.Info) ([]byte, time.Time, error) {
	g.sessions = append(g.sessions, u)
	return []byte(`{}`), g.notAfter, nil
}

func (g *stepUpGenerator) GenerateStepUp(_ storage.Strategy, u userinfo.Info, ttl time.Duration) (time.Time, error) {
	g.stepUps = append(g.stepUps, u)
	g.ttls = append(g.ttls, ttl)
	return g.notAfter, nil
}

// stepUpEnv serves an OIDCConfig named "kc" from a fake apiserver, and an
// IdP token endpoint returning an ID token with the given extra claims.
func stepUpEnv(t *testing.T, stepUp string, claims map[string]any) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := map[string]any{
			"iss": testIssuer, "aud": "portal", "exp": float64(time.Now().Add(time.Hour).Unix()),
			"preferred_username": "alice", "name": "Alice", "picture": "p", "email": "alice@example.com",
			"groups": []any{"devs", "krateo:loa:2"}, // an IdP trying to assert the reserved group
		}
		for k, v := range claims {
			c[k] = v
		}
		payload, _ := json.Marshal(c)
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "at", IDToken: "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"})
	}))
	t.Cleanup(idp.Close)

	spec := `"issuer":"` + testIssuer + `","authorizationURL":"https://idp.example/auth","tokenURL":"` + idp.URL + `",
		"redirectURI":"https://portal.example/auth","clientID":"portal"`
	if stepUp != "" {
		spec += `,"stepUp":` + stepUp
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/oidc.authn.krateo.io/v1alpha1/namespaces/krateo-system/oidcconfigs/kc" {
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"oidc.authn.krateo.io/v1alpha1","kind":"OIDCConfig",
			"metadata":{"name":"kc","namespace":"krateo-system"},"spec":{` + spec + `}}`))
	}))
	t.Cleanup(api.Close)
	return &rest.Config{Host: api.URL}
}

func stepUpRequest(t *testing.T, rc *rest.Config, gen *stepUpGenerator) *httptest.ResponseRecorder {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	route := StepUp(t.Context(), rc, StepUpOptions{KubeconfigGenerator: gen, JwtPrivateKey: key, JwtKeyID: "k"})

	req := httptest.NewRequest(http.MethodPost, StepUpPath+"?name=kc", nil)
	req.Header.Set("X-Auth-Code", "code")
	rec := httptest.NewRecorder()
	route.Handler().ServeHTTP(rec, req)
	return rec
}

const stepUpGold = `{"acrValues":["gold"],"ttl":"20m"}`

// A proven, fresh step-up mints only a step-up credential, carrying exactly
// the granted krateo:loa:2. It never touches the session credential, and the
// token is bounded by the step-up certificate.
func TestStepUpGrantsAShortLivedCredential(t *testing.T) {
	rc := stepUpEnv(t, stepUpGold, map[string]any{"acr": "gold", "auth_time": float64(time.Now().Add(-time.Minute).Unix())})
	gen := &stepUpGenerator{notAfter: time.Now().Add(12 * time.Minute)} // the signer granted less than asked

	rec := stepUpRequest(t, rc, gen)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	assert.Empty(t, gen.sessions, "the session credential is never minted by a step-up")
	require.Len(t, gen.stepUps, 1)
	assert.Equal(t, "alice", gen.stepUps[0].GetUserName())
	assert.Equal(t, []string{"devs", "krateo:loa:2"}, gen.stepUps[0].GetGroups(), "the IdP's copy is dropped, authn's grant added")
	assert.Equal(t, []time.Duration{20 * time.Minute}, gen.ttls)

	var out map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.NotContains(t, out, "data", "no kubeconfig in the response")

	var tok string
	require.NoError(t, json.Unmarshal(out["accessToken"], &tok))
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tok, claims)
	require.NoError(t, err)
	assert.Equal(t, []any{"devs", "krateo:loa:2"}, claims["groups"], "snowplow keys on the group in the token")
	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.WithinDuration(t, gen.notAfter, exp.Time, 5*time.Second, "the token ends with the step-up certificate")
}

func TestStepUpRefusals(t *testing.T) {
	fresh := float64(time.Now().Add(-time.Minute).Unix())
	cases := []struct {
		name   string
		stepUp string
		claims map[string]any
		code   int
		cause  string
	}{
		{name: "not enabled", claims: map[string]any{"acr": "gold", "auth_time": fresh}, code: 403, cause: "StepUpNotEnabled"},
		{name: "acr too low", stepUp: stepUpGold, claims: map[string]any{"acr": "silver", "auth_time": fresh}, code: 403, cause: "InsufficientAssurance"},
		{name: "stale authentication", stepUp: stepUpGold, code: 403, cause: "StaleAuthentication",
			claims: map[string]any{"acr": "gold", "auth_time": float64(time.Now().Add(-time.Hour).Unix())}},
		{name: "ttl below the CSR minimum", stepUp: `{"acrValues":["gold"],"ttl":"5m"}`, code: 500, cause: "StepUpMisconfigured",
			claims: map[string]any{"acr": "gold", "auth_time": fresh}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gen := &stepUpGenerator{notAfter: time.Now().Add(15 * time.Minute)}
			rec := stepUpRequest(t, stepUpEnv(t, tc.stepUp, tc.claims), gen)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			var out struct {
				Details struct {
					Causes []struct {
						Reason string `json:"reason"`
					} `json:"causes"`
				} `json:"details"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
			require.Len(t, out.Details.Causes, 1)
			assert.Equal(t, tc.cause, out.Details.Causes[0].Reason)
			assert.Empty(t, gen.stepUps, "nothing is minted for a refused step-up")
			assert.Empty(t, gen.sessions)
			assert.False(t, strings.Contains(rec.Body.String(), "accessToken"))
		})
	}
}
