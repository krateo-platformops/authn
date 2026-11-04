// Package codeexchange classifies a failed authorization-code exchange
// (RFC 6749 §4.1.3) for the OIDC and OAuth logins: the caller's code was
// refused (403), or authn could not complete the exchange (500).
package codeexchange

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/krateo-platformops/authn/internal/status"
)

// Causes of a failed exchange: the values of details.causes[0].reason
// (docs/api.md). They are added, never renamed.
const (
	// CauseAuthorizationCodeRejected: the token endpoint refused the code
	// itself: expired, already used, issued for another redirect URI, or a
	// PKCE verifier that doesn't match (403).
	CauseAuthorizationCodeRejected status.CauseType = "AuthorizationCodeRejected"
	// CauseTokenExchangeFailed: the exchange could not complete for a reason
	// that isn't the code: the token endpoint is unreachable or failing,
	// rejects authn's client credentials, or answers something unusable (500).
	CauseTokenExchangeFailed status.CauseType = "TokenExchangeFailed"
)

// codeRejections are the token endpoint error codes that refuse the code
// itself. invalid_grant is RFC 6749 §5.2's; GitHub, the usual OAuthConfig,
// answers bad_verification_code for the same case.
var codeRejections = map[string]bool{
	"invalid_grant":         true,
	"bad_verification_code": true,
}

// Refusal classifies the token endpoint's error answer: httpStatus is its
// status code, errorCode its "error" parameter (empty when it had none), and
// detail the full answer, which goes to the server log only: the caller is
// told the status and the error code.
func Refusal(httpStatus int, errorCode string, detail error) status.CauseError {
	if codeRejections[errorCode] {
		return status.RefusedPrivately(CauseAuthorizationCodeRejected,
			fmt.Errorf("the identity provider refused the authorization code (%s)", errorCode), detail)
	}
	public := fmt.Errorf("the identity provider's token endpoint answered %d", httpStatus)
	if errorCode != "" {
		public = fmt.Errorf("the identity provider's token endpoint answered %d (%s)", httpStatus, errorCode)
	}
	return status.CauseError{Code: http.StatusInternalServerError, Cause: CauseTokenExchangeFailed, Err: public, Private: detail}
}

// Failed is an exchange that could not complete: no usable answer came back.
// err, which may name internal endpoints, goes to the server log only.
func Failed(err error) status.CauseError {
	return status.CauseError{Code: http.StatusInternalServerError, Cause: CauseTokenExchangeFailed,
		Err: errors.New("the token exchange with the identity provider did not complete"), Private: err}
}
