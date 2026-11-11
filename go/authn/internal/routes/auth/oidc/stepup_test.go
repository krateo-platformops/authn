package oidc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	oidcv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oidc/v1alpha1"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
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
		// An empty acr value would grant a step-up to an ID token with no acr.
		{name: "empty acr value", tok: idToken{authTime: now}, code: 500, cause: CauseStepUpMisconfigured,
			cfg: &stepUpConfig{acrValues: []string{"gold", ""}, maxAge: time.Minute, ttl: 15 * time.Minute}},
		{name: "acr value with a space", tok: fresh, code: 500, cause: CauseStepUpMisconfigured,
			cfg: &stepUpConfig{acrValues: []string{"gold silver"}, maxAge: time.Minute, ttl: 15 * time.Minute}},
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

func TestStepUpExtensions(t *testing.T) {
	const login = "https://idp.example/auth?client_id=portal&redirect_uri=https%3A%2F%2Fportal.example%2Fauth&response_type=code&scope=openid+email&state=xyz"

	ext, err := StepUpExtensions(nil, login)
	require.NoError(t, err)
	assert.Nil(t, ext, "no spec.stepUp, nothing advertised")

	ext, err = StepUpExtensions(&oidcv1alpha1.OIDCStepUp{AcrValues: []string{"gold", "urn:kc:loa2"}}, login)
	require.NoError(t, err)
	assert.Equal(t, "/oidc/stepup", ext["stepUpPath"])
	assert.Equal(t, "gold urn:kc:loa2", ext["stepUpAcrValues"])
	assert.Equal(t, "300", ext["stepUpMaxAge"], "default maxAge 5m")
	assert.Len(t, ext, 4)

	// The step-up URL is the login URL with acr_values and max_age added:
	// every login parameter survives, and the values are encoded.
	got, err := url.Parse(ext["stepUpAuthCodeURL"])
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example/auth", got.Scheme+"://"+got.Host+got.Path)
	want, _ := url.ParseQuery("client_id=portal&redirect_uri=https%3A%2F%2Fportal.example%2Fauth&response_type=code&scope=openid+email&state=xyz")
	want.Set("acr_values", "gold urn:kc:loa2")
	want.Set("max_age", "300")
	assert.Equal(t, want, got.Query())
	assert.Contains(t, ext["stepUpAuthCodeURL"], "acr_values=gold+urn%3Akc%3Aloa2")

	// A login URL that already carries max_age gets authn's.
	ext, err = StepUpExtensions(&oidcv1alpha1.OIDCStepUp{AcrValues: []string{"gold"}, MaxAge: &metav1.Duration{Duration: 90 * time.Second}},
		"https://idp.example/auth?client_id=portal&max_age=9999")
	require.NoError(t, err)
	assert.Equal(t, "90", ext["stepUpMaxAge"])
	got, err = url.Parse(ext["stepUpAuthCodeURL"])
	require.NoError(t, err)
	assert.Equal(t, []string{"90"}, got.Query()["max_age"])

	for name, spec := range map[string]*oidcv1alpha1.OIDCStepUp{
		"no acr values":       {},
		"empty acr":           {AcrValues: []string{""}},
		"ttl too short":       {AcrValues: []string{"gold"}, TTL: &metav1.Duration{Duration: time.Minute}},
		"non-positive maxAge": {AcrValues: []string{"gold"}, MaxAge: &metav1.Duration{}},
	} {
		ext, err := StepUpExtensions(spec, login)
		var ce status.CauseError
		assert.True(t, errors.As(err, &ce) && ce.Cause == CauseStepUpMisconfigured, "%s: want StepUpMisconfigured, got %v", name, err)
		assert.Nil(t, ext, "%s: a misconfigured step-up is never advertised", name)
	}

	for _, bad := range []string{"", "/auth?client_id=portal", "://bad"} {
		ext, err := StepUpExtensions(&oidcv1alpha1.OIDCStepUp{AcrValues: []string{"gold"}}, bad)
		assert.Error(t, err, "authCodeURL %q", bad)
		assert.Nil(t, ext, "authCodeURL %q: nothing advertised", bad)
	}
}

// stepUpGenerator records what the handler asks the generator to mint.
type stepUpGenerator struct {
	sessions []userinfo.Info
	stepUps  []userinfo.Info
	ttls     []time.Duration
	notAfter time.Time
	// records holds what the route's audit Recorder wrote (AUDIT-4).
	records *audittest.Recorder
}

func (g *stepUpGenerator) Generate(_ storage.Strategy, u userinfo.Info, opts ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	if err := kubeconfig.NewIssueOptions(opts...).CheckAdmit(u); err != nil {
		return kubeconfig.Issued{Secret: storage.Written{Namespace: "krateo-system",
			Name: storage.ClientConfigSecretName(u.GetUserName()), Verb: "create"}}, err
	}
	g.sessions = append(g.sessions, u)
	return kubeconfig.Issued{Kubeconfig: []byte(`{}`), NotAfter: g.notAfter, Secret: auditlogtest.Created(u.GetUserName())}, nil
}

func (g *stepUpGenerator) GenerateStepUp(_ storage.Strategy, u userinfo.Info, ttl time.Duration, opts ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	stepUpSecret := storage.Written{Namespace: "krateo-system", Name: storage.StepUpSecretName(u.GetUserName()), Verb: "create"}
	if err := kubeconfig.NewIssueOptions(opts...).CheckAdmit(u); err != nil {
		return kubeconfig.Issued{Secret: stepUpSecret}, err
	}
	g.stepUps = append(g.stepUps, u)
	g.ttls = append(g.ttls, ttl)
	stepUpSecret.UID, stepUpSecret.ResourceVersion, stepUpSecret.StatusCode = "uid-up", "1", 201
	return kubeconfig.Issued{NotAfter: g.notAfter, Secret: stepUpSecret}, nil
}

// stepUpEnv serves an OIDCConfig named "kc" from a fake apiserver, and an
// IdP token endpoint returning an ID token with the given extra claims.
func stepUpEnv(t *testing.T, stepUp string, claims map[string]any) *rest.Config {
	t.Helper()
	extra := ""
	if stepUp != "" {
		extra = `"stepUp":` + stepUp
	}
	return oidcEnv(t, extra, claims)
}

// oidcEnv is stepUpEnv with any extra OIDCConfig spec fields (JSON members,
// comma-separated, without braces).
func oidcEnv(t *testing.T, extraSpec string, claims map[string]any) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := map[string]any{
			"iss": testIssuer, "sub": "idp-user-1", "aud": "portal", "exp": float64(time.Now().Add(time.Hour).Unix()),
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
	if extraSpec != "" {
		spec += `,` + extraSpec
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
	audit, records := auditlogtest.New(t)
	gen.records = records
	route := StepUp(t.Context(), rc, StepUpOptions{KubeconfigGenerator: gen, Audit: audit, JwtPrivateKey: key, JwtKeyID: "k"})

	req := httptest.NewRequest(http.MethodPost, StepUpPath+"?name=kc", nil)
	req.Header.Set("X-Auth-Code", "code")
	req.Header.Set("X-Code-Verifier", testCodeVerifier)
	rec := httptest.NewRecorder()
	auditlog.Middleware(route.Handler()).ServeHTTP(rec, req)
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
	assert.NotContains(t, out, "strategy", "a step-up token is not a session")

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
		// The record (authn#132): the ID token verified, so every refusal is
		// denied with its reason and a misconfiguration is authn's failure.
		outcome, reason string
	}{
		{name: "not enabled", claims: map[string]any{"acr": "gold", "auth_time": fresh}, code: 403, cause: "StepUpNotEnabled",
			outcome: "denied", reason: "stepup_not_enabled"},
		{name: "acr too low", stepUp: stepUpGold, claims: map[string]any{"acr": "silver", "auth_time": fresh}, code: 403, cause: "InsufficientAssurance",
			outcome: "denied", reason: "insufficient_assurance"},
		{name: "no auth_time", stepUp: stepUpGold, claims: map[string]any{"acr": "gold"}, code: 403, cause: "StaleAuthentication",
			outcome: "denied", reason: "stale_authentication"},
		{name: "stale authentication", stepUp: stepUpGold, code: 403, cause: "StaleAuthentication",
			claims:  map[string]any{"acr": "gold", "auth_time": float64(time.Now().Add(-time.Hour).Unix())},
			outcome: "denied", reason: "stale_authentication"},
		{name: "ttl below the CSR minimum", stepUp: `{"acrValues":["gold"],"ttl":"5m"}`, code: 500, cause: "StepUpMisconfigured",
			claims:  map[string]any{"acr": "gold", "auth_time": fresh},
			outcome: "failure"},
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

			r := auditlogtest.Only(t, gen.records)
			assert.Equal(t, "authn.stepup.oidc", auditlogtest.String(r, "krateo.action"))
			assert.Equal(t, tc.outcome, auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, tc.reason, auditlogtest.String(r, "krateo.audit.denial_reason"))
			assert.True(t, strings.HasSuffix(auditlogtest.String(r, "krateo.audit.object_ref.name"), "-clientconfig-stepup"),
				"the step-up Secret it would have written")
			for _, kv := range audittest.Attributes(r) {
				assert.NotEqual(t, "http.response.status_code", string(kv.Key), "no authority answered")
			}
		})
	}
}

// A refused step-up or login is logged at warn, a step-up authn can't grant
// at error, each with its cause (status.LogFailure).
func TestStepUpLogLevels(t *testing.T) {
	fresh := float64(time.Now().Add(-time.Minute).Unix())
	cases := []struct {
		name   string
		stepUp string
		claims map[string]any
		msg    string
		level  string
		cause  string
	}{
		{name: "acr too low", stepUp: stepUpGold, claims: map[string]any{"acr": "silver", "auth_time": fresh},
			msg: "step-up refused", level: "warn", cause: "InsufficientAssurance"},
		{name: "expired ID token", stepUp: stepUpGold, claims: map[string]any{"acr": "gold", "auth_time": fresh, "exp": float64(time.Now().Add(-time.Hour).Unix())},
			msg: "unable to complete login", level: "warn", cause: "TokenExpired"},
		{name: "ttl below the CSR minimum", stepUp: `{"acrValues":["gold"],"ttl":"5m"}`, claims: map[string]any{"acr": "gold", "auth_time": fresh},
			msg: "step-up refused", level: "error", cause: "StepUpMisconfigured"},
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gen := &stepUpGenerator{notAfter: time.Now().Add(15 * time.Minute)}
			route := StepUp(t.Context(), stepUpEnv(t, tc.stepUp, tc.claims), StepUpOptions{KubeconfigGenerator: gen, JwtPrivateKey: key, JwtKeyID: "k"})

			var buf bytes.Buffer
			req := httptest.NewRequest(http.MethodPost, StepUpPath+"?name=kc", nil)
			req = req.WithContext(zerolog.New(&buf).WithContext(req.Context()))
			req.Header.Set("X-Auth-Code", "code")
			req.Header.Set("X-Code-Verifier", testCodeVerifier)
			route.Handler().ServeHTTP(httptest.NewRecorder(), req)

			line := logLine(t, &buf, tc.msg)
			assert.Equal(t, tc.level, line["level"])
			assert.Equal(t, tc.cause, line["cause"])
			assert.NotEmpty(t, line["error"])
		})
	}
}

// logLine returns the JSON log line whose message is msg.
func logLine(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for _, l := range bytes.Split(buf.Bytes(), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(l, &m) == nil && m["message"] == msg {
			return m
		}
	}
	t.Fatalf("no %q log line in:\n%s", msg, buf.String())
	return nil
}
