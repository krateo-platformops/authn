package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oidcv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oidc/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const discoveredIssuer = "https://idp.example/realms/krateo"

func discoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 discoveredIssuer,
			"authorization_endpoint": "https://idp.example/auth",
			"token_endpoint":         "https://idp.example/token",
			"userinfo_endpoint":      "https://idp.example/userinfo",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveOIDCConfigIssuer(t *testing.T) {
	disc := discoveryServer(t).URL

	cases := []struct {
		name       string
		spec       oidcv1alpha1.OIDCConfigSpec
		wantIssuer string
		wantToken  string
		conflict   bool
	}{
		{name: "issuer from discovery", spec: oidcv1alpha1.OIDCConfigSpec{DiscoveryURL: disc},
			wantIssuer: discoveredIssuer, wantToken: "https://idp.example/token"},
		{name: "spec.issuer equal to discovery", spec: oidcv1alpha1.OIDCConfigSpec{DiscoveryURL: disc, Issuer: discoveredIssuer},
			wantIssuer: discoveredIssuer, wantToken: "https://idp.example/token"},
		{name: "spec.issuer differs from discovery", conflict: true,
			spec: oidcv1alpha1.OIDCConfigSpec{DiscoveryURL: disc, Issuer: "https://other.example"}},
		{name: "explicit endpoints are kept, issuer still discovered",
			spec: oidcv1alpha1.OIDCConfigSpec{DiscoveryURL: disc, AuthorizationURL: "https://mine/auth",
				TokenURL: "https://mine/token", UserInfoURL: "https://mine/userinfo"},
			wantIssuer: discoveredIssuer, wantToken: "https://mine/token"},
		{name: "hand-configured with spec.issuer",
			spec:       oidcv1alpha1.OIDCConfigSpec{Issuer: "https://mine", AuthorizationURL: "https://mine/auth", TokenURL: "https://mine/token"},
			wantIssuer: "https://mine", wantToken: "https://mine/token"},
		{name: "hand-configured without issuer leaves it empty",
			spec:      oidcv1alpha1.OIDCConfigSpec{AuthorizationURL: "https://mine/auth", TokenURL: "https://mine/token"},
			wantToken: "https://mine/token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &oidcv1alpha1.OIDCConfig{Spec: tc.spec}
			err := resolveOIDCConfig(context.Background(), cfg)
			if tc.conflict {
				require.ErrorIs(t, err, ErrIssuerConflict)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantIssuer, cfg.Spec.Issuer)
			assert.Equal(t, tc.wantToken, cfg.Spec.TokenURL)
			assert.True(t, strings.Contains(cfg.Spec.AuthorizationURL, "response_type=code"), cfg.Spec.AuthorizationURL)
		})
	}
}
