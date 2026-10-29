package oidc

import (
	"errors"
	"fmt"
	"time"

	"github.com/krateo-platformops/authn/internal/status"
)

// Causes are the machine-readable reasons an OIDC login fails, returned in
// the Status body's details.causes[].reason. They are part of the API contract
// (docs/api.md): values are added, never renamed, and a cause never changes
// its code.
const (
	// Refusals of the ID token (403): retrying unchanged fails again.
	CauseIDTokenInvalid   status.CauseType = "IDTokenInvalid"
	CauseIssuerMismatch   status.CauseType = "IssuerMismatch"
	CauseAudienceMismatch status.CauseType = "AudienceMismatch"
	CauseTokenExpired     status.CauseType = "TokenExpired"

	// Failures of authn's configuration (500).
	CauseIssuerUnknown  status.CauseType = "IssuerUnknown"
	CauseIssuerConflict status.CauseType = "IssuerConflict"
)

// clockSkew is how far past exp an ID token is still accepted, to absorb
// clock drift between authn and the IdP.
const clockSkew = time.Minute

var errIssuerUnknown = errors.New("no issuer to validate the ID token against: set spec.issuer or spec.discoveryURL")

// validateIDToken checks the claims OIDC Core §3.1.3.7 requires of an ID
// token received from the token endpoint: iss, aud (with azp when there are
// several audiences) and exp. The signature is not checked: the token comes
// back-channel from the configured token endpoint, authenticated with the
// client secret over TLS, which §3.1.3.7 accepts in place of it.
func validateIDToken(claims map[string]any, issuer, clientID string, now time.Time) error {
	if issuer == "" {
		return status.Failed(CauseIssuerUnknown, errIssuerUnknown)
	}

	iss, _ := claims["iss"].(string)
	if iss != issuer {
		return status.Refused(CauseIssuerMismatch, fmt.Errorf("ID token issuer %q, expected %q", iss, issuer))
	}

	aud, err := audiences(claims["aud"])
	if err != nil {
		return status.Refused(CauseIDTokenInvalid, err)
	}
	if !contains(aud, clientID) {
		return status.Refused(CauseAudienceMismatch, fmt.Errorf("ID token audience %q does not include client %q", aud, clientID))
	}
	if len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != clientID {
			return status.Refused(CauseAudienceMismatch, fmt.Errorf("ID token has several audiences and azp %q is not client %q", azp, clientID))
		}
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return status.Refused(CauseIDTokenInvalid, errors.New("ID token has no numeric exp"))
	}
	if expiry := time.Unix(int64(exp), 0); now.After(expiry.Add(clockSkew)) {
		return status.Refused(CauseTokenExpired, fmt.Errorf("ID token expired at %s", expiry.UTC().Format(time.RFC3339)))
	}

	return nil
}

// audiences reads aud, which OIDC allows as a single string or an array.
func audiences(v any) ([]string, error) {
	switch aud := v.(type) {
	case string:
		return []string{aud}, nil
	case []any:
		out := make([]string, 0, len(aud))
		for _, a := range aud {
			s, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("ID token aud has a non-string value %v", a)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("ID token has no aud")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
