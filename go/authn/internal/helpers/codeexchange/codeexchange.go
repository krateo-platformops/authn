// Package codeexchange classifies a failed authorization-code exchange
// (RFC 6749 §4.1.3) for the OIDC and OAuth logins: the caller's code was
// refused (403), or authn could not complete the exchange (500).
package codeexchange

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
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
// detail the full answer. The caller is told the status and the error code;
// the log gets the same. Neither ever carries error_description or the body,
// which an IdP may fill with the user's name or email (Diego, 2026-11-12).
func Refusal(httpStatus int, errorCode string, detail error) status.CauseError {
	code := ErrorCode(errorCode)
	private := kerr.Described(fmt.Sprintf("the token endpoint answered %d (%s)", httpStatus, code), detail)
	if codeRejections[errorCode] {
		return status.RefusedPrivately(CauseAuthorizationCodeRejected,
			fmt.Errorf("the identity provider refused the authorization code (%s)", code), private)
	}
	public := fmt.Errorf("the identity provider's token endpoint answered %d", httpStatus)
	if errorCode != "" {
		public = fmt.Errorf("the identity provider's token endpoint answered %d (%s)", httpStatus, code)
	}
	return status.CauseError{Code: http.StatusInternalServerError, Cause: CauseTokenExchangeFailed, Err: public, Private: private}
}

// registeredErrors are the token endpoint error codes OAuth 2.0 and OpenID
// Connect register (RFC 6749 §5.2, RFC 6750, OIDC Core §3.1.2.6, RFC 8628,
// RFC 9449), and GitHub's own.
var registeredErrors = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true, "unauthorized_client": true,
	"unsupported_grant_type": true, "invalid_scope": true, "access_denied": true, "unsupported_response_type": true,
	"server_error": true, "temporarily_unavailable": true, "invalid_token": true, "insufficient_scope": true,
	"interaction_required": true, "login_required": true, "account_selection_required": true, "consent_required": true,
	"invalid_request_uri": true, "invalid_request_object": true, "request_not_supported": true,
	"request_uri_not_supported": true, "registration_not_supported": true, "authorization_pending": true,
	"slow_down": true, "expired_token": true, "invalid_dpop_proof": true, "use_dpop_nonce": true,
	"bad_verification_code": true, "incorrect_client_credentials": true, "redirect_uri_mismatch": true,
}

// ErrorCode is a token endpoint's "error" parameter as authn repeats it: the
// code itself when it is a registered one, a placeholder otherwise, since an
// IdP can put any text there.
func ErrorCode(code string) string {
	switch {
	case code == "":
		return "no error code"
	case registeredErrors[code]:
		return code
	}
	return "an unregistered error code"
}

// Failed is an exchange that could not complete: no usable answer came back.
// err, which may name internal endpoints, goes to the server log only.
func Failed(err error) status.CauseError {
	return status.CauseError{Code: http.StatusInternalServerError, Cause: CauseTokenExchangeFailed,
		Err: errors.New("the token exchange with the identity provider did not complete"), Private: err}
}
