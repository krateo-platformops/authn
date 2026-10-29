package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateIDToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	valid := func() map[string]any {
		return map[string]any{"iss": testIssuer, "aud": "client", "exp": float64(now.Add(time.Hour).Unix())}
	}
	with := func(k string, v any) map[string]any {
		c := valid()
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}

	cases := []struct {
		name   string
		claims map[string]any
		issuer string
		code   int
		cause  status.CauseType
	}{
		{name: "valid", claims: valid(), issuer: testIssuer},
		{name: "aud as an array", claims: with("aud", []any{"client"}), issuer: testIssuer},
		{name: "several audiences with azp", issuer: testIssuer,
			claims: func() map[string]any { c := with("aud", []any{"other", "client"}); c["azp"] = "client"; return c }()},
		{name: "expired within the clock skew", claims: with("exp", float64(now.Add(-30*time.Second).Unix())), issuer: testIssuer},

		{name: "no expected issuer", claims: valid(), issuer: "", code: 500, cause: CauseIssuerUnknown},
		{name: "no expected issuer and no iss claim", claims: with("iss", nil), issuer: "", code: 500, cause: CauseIssuerUnknown},
		{name: "other issuer", claims: with("iss", "https://evil.example"), issuer: testIssuer, code: 403, cause: CauseIssuerMismatch},
		{name: "no iss", claims: with("iss", nil), issuer: testIssuer, code: 403, cause: CauseIssuerMismatch},
		{name: "issuer differs by a trailing slash", claims: with("iss", testIssuer+"/"), issuer: testIssuer, code: 403, cause: CauseIssuerMismatch},
		{name: "other audience", claims: with("aud", "other"), issuer: testIssuer, code: 403, cause: CauseAudienceMismatch},
		{name: "several audiences without azp", claims: with("aud", []any{"other", "client"}), issuer: testIssuer, code: 403, cause: CauseAudienceMismatch},
		{name: "several audiences, azp another client", issuer: testIssuer, code: 403, cause: CauseAudienceMismatch,
			claims: func() map[string]any { c := with("aud", []any{"other", "client"}); c["azp"] = "other"; return c }()},
		{name: "no aud", claims: with("aud", nil), issuer: testIssuer, code: 403, cause: CauseIDTokenInvalid},
		{name: "non-string aud", claims: with("aud", []any{"client", 7.0}), issuer: testIssuer, code: 403, cause: CauseIDTokenInvalid},
		{name: "no exp", claims: with("exp", nil), issuer: testIssuer, code: 403, cause: CauseIDTokenInvalid},
		{name: "exp as a string", claims: with("exp", "1800003600"), issuer: testIssuer, code: 403, cause: CauseIDTokenInvalid},
		{name: "expired", claims: with("exp", float64(now.Add(-2*time.Minute).Unix())), issuer: testIssuer, code: 403, cause: CauseTokenExpired},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIDToken(tc.claims, tc.issuer, "client", now)
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

// doLogin must refuse an ID token that fails validation, before reading any
// identity from it.
func TestDoLoginRejectsInvalidIDToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := json.Marshal(map[string]any{
			"iss": "https://evil.example", "aud": "test-client-id", "exp": float64(time.Now().Add(time.Hour).Unix()),
			"preferred_username": "admin", "groups": []any{"admins"},
		})
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "a",
			IDToken:     "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig",
		})
	}))
	defer srv.Close()

	tok, err := doLogin(context.Background(), "code", &oidcConfig{
		Issuer: testIssuer, ClientID: "test-client-id", TokenURL: srv.URL,
	})
	var ce status.CauseError
	require.True(t, errors.As(err, &ce), "want a CauseError, got %v", err)
	assert.Equal(t, CauseIssuerMismatch, ce.Cause)
	assert.Empty(t, tok.preferredUsername)
	assert.Empty(t, tok.groups)
}
