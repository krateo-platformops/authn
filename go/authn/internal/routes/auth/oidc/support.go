package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/codeexchange"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/outbound"
	"github.com/krateo-platformops/authn/internal/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

type oidcConfig struct {
	// StepUp is nil when the OIDCConfig doesn't enable step-up.
	StepUp        *stepUpConfig
	AllowedGroups []string
	DiscoveryURL  string
	Issuer        string
	AuthorizeURL  string
	TokenURL      string
	UserInfoURL   string
	RedirectURI   string
	ClientID      string
	// Public is true when the OIDCConfig names no clientSecret: no
	// client_secret is sent, and a login must carry a PKCE verifier.
	Public           bool
	ClientSecret     string
	AdditionalScopes string
	RESTActionRef    *core.ObjectRef
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IDToken     string `json:"id_token"`
}

type idToken struct {
	// acr and authTime come from the validated ID token only, never from the
	// RESTAction (updateConfig can't set them): they are what a step-up login
	// proves.
	acr      string
	authTime time.Time

	// issuer and subject are the ID token's iss and sub, which name the
	// authenticated identity. Like acr, they come from the validated ID token
	// only, never from the RESTAction or UserInfo.
	issuer  string
	subject string

	bearerToken       string
	name              string
	email             string
	preferredUsername string
	groups            []string
	avatarURL         string
}

func getConfig(ctx context.Context, rc *rest.Config, name string) (*oidcConfig, error) {
	if len(rest.IsValidPathSegmentName(name)) > 0 {
		// No OIDCConfig can have this name; looking it up would fail client-side.
		return &oidcConfig{}, status.CauseError{Code: http.StatusNotFound, Cause: CauseOIDCConfigNotFound,
			Err: fmt.Errorf("OIDCConfig %q not found", name)}
	}
	cfg, err := resolvers.OIDCConfigGet(ctx, rc, name)
	switch {
	case apierrors.IsNotFound(err):
		return &oidcConfig{}, status.CauseError{Code: http.StatusNotFound, Cause: CauseOIDCConfigNotFound,
			Err: fmt.Errorf("OIDCConfig %q not found", name)}
	case errors.Is(err, resolvers.ErrIssuerConflict):
		return &oidcConfig{}, status.Failed(CauseIssuerConflict, err)
	case errors.Is(err, resolvers.ErrDiscoveryFailed):
		return &oidcConfig{}, status.Failed(CauseOIDCDiscoveryFailed, err)
	case errors.Is(err, resolvers.ErrEndpointsMissing):
		return &oidcConfig{}, status.Failed(CauseOIDCConfigInvalid, err)
	case err != nil:
		return &oidcConfig{}, status.Failed(CauseOIDCConfigLookupFailed, fmt.Errorf("unable to resolve OIDC configuration: %w", err))
	}

	res := &oidcConfig{
		DiscoveryURL:     cfg.Spec.DiscoveryURL,
		Issuer:           cfg.Spec.Issuer,
		AuthorizeURL:     cfg.Spec.AuthorizationURL,
		TokenURL:         cfg.Spec.TokenURL,
		RedirectURI:      cfg.Spec.RedirectURI,
		UserInfoURL:      cfg.Spec.UserInfoURL,
		ClientID:         cfg.Spec.ClientID,
		AdditionalScopes: cfg.Spec.AdditionalScopes,
		RESTActionRef:    cfg.Spec.RESTActionRef,
		StepUp:           resolveStepUp(cfg.Spec.StepUp),
		AllowedGroups:    cfg.Spec.AllowedGroups,
	}

	ref := cfg.Spec.ClientSecret
	if ref == nil {
		res.Public = true
		return res, nil
	}
	sec, err := secrets.Get(context.Background(), rc, ref)
	if err != nil {
		return res, status.Failed(CauseClientSecretLookupFailed, fmt.Errorf("unable to read the client secret: %w", err))
	}
	// A named secret that resolves to nothing must not turn the client into
	// a public one, or send an empty client_secret.
	val, ok := sec.Data[ref.Key]
	if !ok || len(val) == 0 {
		return res, status.Failed(CauseClientSecretLookupFailed, fmt.Errorf("the client secret %s/%s has no value under key %q", ref.Namespace, ref.Name, ref.Key))
	}
	res.ClientSecret = string(val)

	return res, nil
}

// doLogin exchanges the authorization code for tokens and returns the
// validated identity. codeVerifier is the PKCE verifier (RFC 7636) the client
// generated for this authorization request; it is forwarded when present, so
// an IdP that requires PKCE accepts the exchange. Empty means the request used
// no PKCE, which a public client (cfg.Public) refuses before calling the IdP:
// with no secret, the verifier is the only proof that the caller started the
// sign-in.
func doLogin(ctx context.Context, code, codeVerifier string, cfg *oidcConfig) (idToken, error) {
	if cfg.Public && codeVerifier == "" {
		return idToken{}, status.BadRequest(CauseMissingCodeVerifier,
			fmt.Errorf("this OIDCConfig is a public client: the %s header must carry the PKCE verifier", codeVerifierKey))
	}
	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	if !cfg.Public {
		data.Set("client_secret", cfg.ClientSecret)
	}
	data.Set("code", code)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}
	data.Set("redirect_uri", cfg.RedirectURI)
	data.Set("grant_type", "authorization_code")

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL,
		strings.NewReader(data.Encode()))
	if err != nil {
		return idToken{}, codeexchange.Failed(fmt.Errorf("failed to create request to token endpoint: %v", err))
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	resp, err := outbound.Client().Do(tokenReq)
	if err != nil {
		return idToken{}, codeexchange.Failed(fmt.Errorf("failed to send request to token endpoint: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return idToken{}, codeexchange.Failed(fmt.Errorf("failed to read response body: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		// RFC 6749 §5.2: an error answer is JSON with an "error" code.
		var answer struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &answer)
		return idToken{}, codeexchange.Refusal(resp.StatusCode, answer.Error,
			fmt.Errorf("token endpoint answered %d: %s", resp.StatusCode, string(body)))
	}

	var token TokenResponse
	err = json.Unmarshal(body, &token)
	if err != nil {
		return idToken{}, codeexchange.Failed(fmt.Errorf("failed to unmarshal token response: %v", err))
	}

	claims, err := decodeJWT(token.IDToken)
	if err != nil {
		return idToken{}, status.Refused(CauseIDTokenInvalid, fmt.Errorf("failed to decode JWT token: %v", err))
	}

	if err := validateIDToken(claims, cfg.Issuer, cfg.ClientID, time.Now()); err != nil {
		return idToken{}, err
	}

	invalid := func(key string, err error) (idToken, error) {
		return idToken{}, status.Refused(CauseIDTokenInvalid, fmt.Errorf("ID token claim %s %w", key, err))
	}

	var res idToken
	var err2 error
	if res.acr, _, err2 = stringClaim(claims, "acr"); err2 != nil {
		return invalid("acr", err2)
	}
	// validateIDToken has checked iss. sub is required (OIDC Core 2): it is
	// the only stable name of the identity.
	res.issuer, _ = claims["iss"].(string)
	var hasSub bool
	if res.subject, hasSub, err2 = stringClaim(claims, "sub"); err2 != nil {
		return invalid("sub", err2)
	}
	if !hasSub || res.subject == "" {
		return invalid("sub", errMissing)
	}
	if v, ok := claims["auth_time"]; ok && v != nil {
		at, isNumber := v.(float64)
		if !isNumber {
			return invalid("auth_time", errNotANumber)
		}
		res.authTime = time.Unix(int64(at), 0)
	}

	// The profile claims, read from the ID token. Any it omits is asked of the
	// UserInfo endpoint, when there is one.
	profile := []struct {
		key string
		dst *string
	}{
		{"preferred_username", &res.preferredUsername},
		{"name", &res.name},
		{"picture", &res.avatarURL},
		{"email", &res.email},
	}
	var missing []int
	for i, c := range profile {
		v, ok, err := stringClaim(claims, c.key)
		if err != nil {
			return invalid(c.key, err)
		}
		if !ok {
			missing = append(missing, i)
			continue
		}
		*c.dst = v
	}

	res.bearerToken = token.AccessToken

	// groups is never asked of UserInfo: it isn't part of its standard answer.
	if res.groups, _, err2 = stringListClaim(claims, "groups"); err2 != nil {
		return invalid("groups", err2)
	}

	if len(missing) == 0 || cfg.UserInfoURL == "" {
		return res, nil
	}
	if token.AccessToken == "" {
		return idToken{}, codeexchange.Failed(errors.New("the token response has no access_token, which the userinfo call needs"))
	}
	userInfo, err := fetchUserInfo(ctx, cfg.UserInfoURL, token.AccessToken)
	if err != nil {
		return idToken{}, err
	}
	for _, i := range missing {
		v, ok, err := stringClaim(userInfo, profile[i].key)
		if err != nil {
			return idToken{}, status.Failed(CauseUserInfoFailed, fmt.Errorf("userinfo field %s %w", profile[i].key, err))
		}
		if ok {
			*profile[i].dst = v
		}
	}
	return res, nil
}

// fetchUserInfo asks the UserInfo endpoint for the claims of the user
// accessToken belongs to.
func fetchUserInfo(ctx context.Context, userInfoURL, accessToken string) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, status.Failed(CauseUserInfoFailed, fmt.Errorf("failed to create http request for userinfo endpoint: %v", err))
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	resp, err := outbound.Client().Do(request)
	if err != nil {
		return nil, status.Failed(CauseUserInfoFailed, fmt.Errorf("failed to send userinfo request: %v", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, status.Failed(CauseUserInfoFailed, fmt.Errorf("userinfo endpoint answered %d", resp.StatusCode))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Failed(CauseUserInfoFailed, fmt.Errorf("failed to read userinfo response: %v", err))
	}
	var userInfo map[string]any
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, status.Failed(CauseUserInfoFailed, fmt.Errorf("error parsing userinfo payload JSON: %v", err))
	}
	return userInfo, nil
}

var (
	errNotAString      = errors.New("is not a string")
	errNotANumber      = errors.New("is not a number")
	errNotAStringsList = errors.New("is not a list of strings")
	errMissing         = errors.New("is missing or empty")
)

// stringClaim reads the string claim key of m. A claim that is absent or null
// is not there (ok false): OIDC Core §5.1 asks providers to omit a claim
// rather than send it null, and some send null anyway. Any other non-string
// is an error.
func stringClaim(m map[string]any, key string) (v string, ok bool, err error) {
	raw, present := m[key]
	if !present || raw == nil {
		return "", false, nil
	}
	v, ok = raw.(string)
	if !ok {
		return "", false, errNotAString
	}
	return v, true, nil
}

// stringListClaim reads the claim key of m as a list of strings, with the same
// absent-or-null rule as stringClaim.
func stringListClaim(m map[string]any, key string) (v []string, ok bool, err error) {
	raw, present := m[key]
	if !present || raw == nil {
		return nil, false, nil
	}
	list, isList := raw.([]any)
	if !isList {
		return nil, false, errNotAStringsList
	}
	v = make([]string, 0, len(list))
	for _, item := range list {
		str, isString := item.(string)
		if !isString {
			return nil, false, errNotAStringsList
		}
		v = append(v, str)
	}
	return v, true, nil
}

func decodeJWT(tokenString string) (map[string]interface{}, error) {
	var claims map[string]interface{}
	// Split the token into header, payload, and signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return claims, fmt.Errorf("invalid token: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, fmt.Errorf("error decoding payload: %v", err)
	}

	// Parse the JSON payload
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return claims, fmt.Errorf("error parsing payload JSON: %v", err)
	}

	return claims, nil
}

func updateConfig(config idToken, additionalFieldstoReplace map[string]interface{}) (idToken, error) {
	for key := range additionalFieldstoReplace {
		if additionalFieldstoReplace[key] != nil {
			switch key {
			case "name":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}
				config.name = v
			case "email":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}
				config.email = v
			case "preferredUsername":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}
				config.preferredUsername = v
			case "groups":
				groups := make([]string, 0)
				v, ok := additionalFieldstoReplace[key].([]interface{})
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type array", key)
				}
				for _, i := range v {
					if _, okk := i.(string); !okk {
						return config, fmt.Errorf("error parsing updated config: %s is not type string array", key)
					}
					groups = append(groups, i.(string))
				}
				config.groups = groups
			case "avatarURL":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}

				config.avatarURL = v

			}
		}
	}
	return config, nil
}
