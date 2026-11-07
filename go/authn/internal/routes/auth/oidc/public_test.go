package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// testCodeVerifier is the PKCE verifier the route tests send: their
// OIDCConfigs name no clientSecret, so they are public clients, which refuse
// a login without one.
const testCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// tokenEndpoint answers a valid ID token and records the form of each request.
func tokenEndpoint(t *testing.T) (*httptest.Server, *[]map[string][]string) {
	t.Helper()
	var forms []map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		forms = append(forms, r.PostForm)
		claims, _ := json.Marshal(map[string]interface{}{
			"iss": testIssuer, "aud": "c", "exp": float64(time.Now().Add(time.Hour).Unix()),
			"preferred_username": "u", "name": "n", "picture": "p", "email": "e",
		})
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "a",
			IDToken:     "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".s",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &forms
}

// A public client has no secret, so the PKCE verifier is the only proof that
// the caller started the sign-in: without one, the login is refused before
// the IdP is called.
func TestPublicClientRequiresCodeVerifier(t *testing.T) {
	srv, forms := tokenEndpoint(t)
	_, err := doLogin(context.Background(), "code", "", &oidcConfig{Public: true, Issuer: testIssuer, ClientID: "c", TokenURL: srv.URL})
	require.Error(t, err)
	st := status.FromError(err)
	assert.Equal(t, http.StatusBadRequest, int(st.Code))
	require.NotNil(t, st.Details)
	assert.Equal(t, CauseMissingCodeVerifier, st.Details.Causes[0].Type)
	assert.Empty(t, *forms, "the IdP was called without a verifier")
}

// Only a confidential client sends client_secret; a public one sends none,
// not even an empty one.
func TestClientSecretIsSentOnlyByAConfidentialClient(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    oidcConfig
		secret []string
	}{
		{"public", oidcConfig{Public: true}, nil},
		{"confidential", oidcConfig{ClientSecret: "s3cret"}, []string{"s3cret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, forms := tokenEndpoint(t)
			cfg := tc.cfg
			cfg.Issuer, cfg.ClientID, cfg.TokenURL = testIssuer, "c", srv.URL
			_, err := doLogin(context.Background(), "code", testCodeVerifier, &cfg)
			require.NoError(t, err)
			require.Len(t, *forms, 1)
			got, sent := (*forms)[0]["client_secret"]
			assert.Equal(t, tc.secret != nil, sent, "client_secret sent")
			assert.Equal(t, tc.secret, got)
			assert.Equal(t, []string{testCodeVerifier}, (*forms)[0]["code_verifier"])
		})
	}
}

// configEnv serves the OIDCConfig named kc with clientSecretRef (empty: none)
// and, under /secrets/, a Secret holding data.
func configEnv(t *testing.T, clientSecretRef string, data map[string]string) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	spec := `"issuer":"` + testIssuer + `","authorizationURL":"https://idp.example/auth","tokenURL":"https://idp.example/token",
		"redirectURI":"https://portal.example/auth","clientID":"portal"`
	if clientSecretRef != "" {
		spec += `,"clientSecret":` + clientSecretRef
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/secrets/") {
			enc := map[string]string{}
			for k, v := range data {
				enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": map[string]string{"name": "idp", "namespace": "krateo-system"},
				"data":     enc,
			})
			return
		}
		_, _ = w.Write([]byte(`{"apiVersion":"oidc.authn.krateo.io/v1alpha1","kind":"OIDCConfig",
			"metadata":{"name":"kc","namespace":"krateo-system"},"spec":{` + spec + `}}`))
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// An OIDCConfig without clientSecret is a public client. One that names a
// Secret is confidential, and the Secret must hold a value under the key: a
// missing or empty one fails the login instead of silently sending no secret.
func TestGetConfigClientSecret(t *testing.T) {
	ref := `{"name":"idp","namespace":"krateo-system","key":"secret"}`
	for _, tc := range []struct {
		name   string
		ref    string
		data   map[string]string
		public bool
		secret string
		cause  status.CauseType
	}{
		{name: "no clientSecret is a public client", public: true},
		{name: "a named secret is used", ref: ref, data: map[string]string{"secret": "s3cret"}, secret: "s3cret"},
		{name: "a missing key fails", ref: ref, data: map[string]string{"other": "x"}, cause: CauseClientSecretLookupFailed},
		{name: "an empty value fails", ref: ref, data: map[string]string{"secret": ""}, cause: CauseClientSecretLookupFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := getConfig(context.Background(), configEnv(t, tc.ref, tc.data), "kc")
			if tc.cause != "" {
				require.Error(t, err)
				st := status.FromError(err)
				require.NotNil(t, st.Details)
				assert.Equal(t, tc.cause, st.Details.Causes[0].Type)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.public, cfg.Public)
			assert.Equal(t, tc.secret, cfg.ClientSecret)
		})
	}
}
