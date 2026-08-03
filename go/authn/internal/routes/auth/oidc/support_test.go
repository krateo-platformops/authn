package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog/log"
)

func TestDoLogin(t *testing.T) {
	testCases := []struct {
		name               string
		idTokenClaims      map[string]interface{}
		userInfoResponse   map[string]interface{}
		expectUserInfoCall bool
		expectedToken      idToken
	}{
		{
			name: "Complete JWT Token",
			idTokenClaims: map[string]interface{}{
				"preferred_username": "testuser",
				"name":               "Test User",
				"picture":            "https://example.com/avatar.jpg",
				"email":              "test@example.com",
				"groups":             []interface{}{"group1", "group2"},
			},
			expectUserInfoCall: false,
			expectedToken: idToken{
				bearerToken:       "test-access-token",
				preferredUsername: "testuser",
				name:              "Test User",
				avatarURL:         "https://example.com/avatar.jpg",
				email:             "test@example.com",
				groups:            []string{"group1", "group2"},
			},
		},
		{
			name: "Incomplete JWT Token with UserInfo",
			idTokenClaims: map[string]interface{}{
				"email":  "test@example.com",
				"groups": []interface{}{"group1", "group2"},
			},
			userInfoResponse: map[string]interface{}{
				"preferred_username": "testuser",
				"name":               "Test User",
				"picture":            "https://example.com/avatar.jpg",
			},
			expectUserInfoCall: true,
			expectedToken: idToken{
				bearerToken:       "test-access-token",
				preferredUsername: "testuser",
				name:              "Test User",
				avatarURL:         "https://example.com/avatar.jpg",
				email:             "test@example.com",
				groups:            []string{"group1", "group2"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				err := r.ParseForm()
				if err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}

				// Request parameters
				if r.FormValue("client_id") != "test-client-id" {
					t.Errorf("Expected client_id 'test-client-id', got '%s'", r.FormValue("client_id"))
				}
				if r.FormValue("client_secret") != "test-client-secret" {
					t.Errorf("Expected client_secret 'test-client-secret', got '%s'", r.FormValue("client_secret"))
				}
				if r.FormValue("code") != "test-code" {
					t.Errorf("Expected code 'test-code', got '%s'", r.FormValue("code"))
				}
				if r.FormValue("redirect_uri") != "http://example.com/callback" {
					t.Errorf("Expected redirect_uri 'http://example.com/callback', got '%s'", r.FormValue("redirect_uri"))
				}
				if r.FormValue("grant_type") != "authorization_code" {
					t.Errorf("Expected grant_type 'authorization_code', got '%s'", r.FormValue("grant_type"))
				}

				// Fake JWT
				header := map[string]string{"alg": "none", "typ": "JWT"}
				headerJSON, _ := json.Marshal(header)
				headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)

				payloadJSON, _ := json.Marshal(tc.idTokenClaims)
				payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

				idToken := headerBase64 + "." + payloadBase64 + ".signature"

				token := TokenResponse{
					AccessToken: "test-access-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
					Scope:       "openid profile email",
					IDToken:     idToken,
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(token)
			}))
			defer tokenServer.Close()

			// Create a test server for userinfo endpoint if needed
			var userInfoServer *httptest.Server
			if tc.expectUserInfoCall {
				userInfoServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Errorf("Expected GET request, got %s", r.Method)
					}

					auth := r.Header.Get("Authorization")
					expectedAuth := "Bearer test-access-token"
					if auth != expectedAuth {
						t.Errorf("Expected Authorization header '%s', got '%s'", expectedAuth, auth)
					}

					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(tc.userInfoResponse)
				}))
				defer userInfoServer.Close()
			}

			cfg := &oidcConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURI:  "http://example.com/callback",
				TokenURL:     tokenServer.URL,
			}

			if tc.expectUserInfoCall {
				cfg.UserInfoURL = userInfoServer.URL
			}

			// FuT
			resultToken, err := doLogin(context.Background(), "test-code", cfg)
			if err != nil {
				t.Fatalf("doLogin failed: %v", err)
			}

			if resultToken.bearerToken != tc.expectedToken.bearerToken {
				t.Errorf("Expected bearerToken '%s', got '%s'", tc.expectedToken.bearerToken, resultToken.bearerToken)
			}
			if resultToken.preferredUsername != tc.expectedToken.preferredUsername {
				t.Errorf("Expected preferredUsername '%s', got '%s'", tc.expectedToken.preferredUsername, resultToken.preferredUsername)
			}
			if resultToken.name != tc.expectedToken.name {
				t.Errorf("Expected name '%s', got '%s'", tc.expectedToken.name, resultToken.name)
			}
			if resultToken.avatarURL != tc.expectedToken.avatarURL {
				t.Errorf("Expected avatarURL '%s', got '%s'", tc.expectedToken.avatarURL, resultToken.avatarURL)
			}
			if resultToken.email != tc.expectedToken.email {
				t.Errorf("Expected email '%s', got '%s'", tc.expectedToken.email, resultToken.email)
			}
			if len(resultToken.groups) != len(tc.expectedToken.groups) {
				t.Errorf("Expected %d groups, got %d", len(tc.expectedToken.groups), len(resultToken.groups))
			} else {
				for i, group := range tc.expectedToken.groups {
					if resultToken.groups[i] != group {
						t.Errorf("Expected group[%d] = '%s', got '%s'", i, group, resultToken.groups[i])
					}
				}
			}
		})
	}
}

func TestDecodeJWT(t *testing.T) {
	// Fake JWT
	payload := map[string]interface{}{
		"preferred_username": "testuser",
		"name":               "Test User",
		"picture":            "https://example.com/avatar.jpg",
		"email":              "test@example.com",
		"groups":             []interface{}{"group1", "group2"},
	}
	header := map[string]string{"alg": "none", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	dataOk := headerBase64 + "." + payloadBase64 + ".signature"

	claims, err := decodeJWT(dataOk)
	if err != nil {
		t.Fatal(err)
	}

	for key := range claims {
		if _, ok := claims[key].(string); ok {
			if claims[key] != payload[key] {
				t.Fatal(fmt.Errorf("incorrect map: %s value: %s, expected value: %s", key, claims[key], payload[key]))
			}
		} else if a, ok := claims[key].([]interface{}); ok {
			for i, uv := range a {
				if v, okk := uv.(string); okk {
					if v != payload[key].([]interface{})[i].(string) {
						t.Fatal(fmt.Errorf("incorrect map: %s value: %s, expected value: %s", key, v, payload[key].([]interface{})[i].(string)))
					}
				}
			}
		}
	}
}

func TestConfigUpdate(t *testing.T) {
	dataOk := make(map[string]interface{})
	dataFailureEmail := make(map[string]interface{})
	dataFailureGroup := make(map[string]interface{})
	dataFailureStringInGroup := make(map[string]interface{})

	dataOk["name"] = "test"
	dataOk["email"] = "test@test.com"
	dataOk["preferredUsername"] = "test"
	dataOk["groups"] = []interface{}{"groupA", "groupB"}
	dataOk["avatarURL"] = "http://image.avatar.com"

	dataFailureEmail["name"] = "test"
	dataFailureEmail["email"] = 4
	dataFailureEmail["preferredUsername"] = "test"
	dataFailureEmail["groups"] = []interface{}{"groupA", "groupB"}
	dataFailureEmail["avatarURL"] = "http://image.avatar.com"

	dataFailureGroup["name"] = "test"
	dataFailureGroup["email"] = "test@test.com"
	dataFailureGroup["preferredUsername"] = "test"
	dataFailureGroup["groups"] = "groupA"
	dataFailureGroup["avatarURL"] = "http://image.avatar.com"

	dataFailureStringInGroup["name"] = "test"
	dataFailureStringInGroup["email"] = "test@test.com"
	dataFailureStringInGroup["preferredUsername"] = "test"
	dataFailureStringInGroup["groups"] = []int{123, 456}
	dataFailureStringInGroup["avatarURL"] = "http://image.avatar.com"

	config := idToken{}
	config, err := updateConfig(config, dataOk)
	if err != nil {
		t.Fatal(err)
	}
	if config.name != "test" || config.email != "test@test.com" || config.preferredUsername != "test" || config.avatarURL != "http://image.avatar.com" || config.groups[0] != "groupA" || config.groups[1] != "groupB" {
		t.Fatal(fmt.Errorf("parsing incorrect, values not matching: %s", config))
	}

	config = idToken{}
	config, err = updateConfig(config, dataFailureEmail)
	if err == nil {
		t.Fatal(fmt.Errorf("parsing incorrect, email is not string but did not fail"))
	} else {
		log.Logger.Info().Msgf("obtained expected error: %s", err)
	}

	config = idToken{}
	config, err = updateConfig(config, dataFailureGroup)
	if err == nil {
		t.Fatal(fmt.Errorf("parsing incorrect, group is not array but did not fail"))
	} else {
		log.Logger.Info().Msgf("obtained expected error: %s", err)
	}

	config = idToken{}
	config, err = updateConfig(config, dataFailureStringInGroup)
	if err == nil {
		t.Fatal(fmt.Errorf("parsing incorrect, group array is not string but did not fail"))
	} else {
		log.Logger.Info().Msgf("obtained expected error: %s", err)
	}

}
