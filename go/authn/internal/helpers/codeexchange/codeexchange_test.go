package codeexchange

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRefusal(t *testing.T) {
	detail := errors.New("the full answer, for the log")

	for _, code := range []string{"invalid_grant", "bad_verification_code"} {
		ce := Refusal(http.StatusBadRequest, code, detail)
		assert.Equal(t, http.StatusForbidden, ce.Code, code)
		assert.Equal(t, CauseAuthorizationCodeRejected, ce.Cause, code)
		assert.ErrorIs(t, ce.Private, detail, code)
		assert.NotContains(t, ce.Error(), "full answer", code)
		assert.NotContains(t, ce.Private.Error(), "full answer", "the log gets the code, never the answer")
	}

	for _, tc := range []struct {
		status int
		code   string
	}{
		{http.StatusUnauthorized, "invalid_client"},
		{http.StatusBadRequest, "invalid_request"},
		{http.StatusBadRequest, "unauthorized_client"},
		{http.StatusBadGateway, ""},
	} {
		ce := Refusal(tc.status, tc.code, detail)
		assert.Equal(t, http.StatusInternalServerError, ce.Code, tc.code)
		assert.Equal(t, CauseTokenExchangeFailed, ce.Cause, tc.code)
		assert.ErrorIs(t, ce.Private, detail, tc.code)
		assert.NotContains(t, ce.Error(), "full answer", tc.code)
		assert.NotContains(t, ce.Private.Error(), "full answer", tc.code)
	}
}

func TestFailedKeepsTheReasonPrivate(t *testing.T) {
	err := errors.New("dial tcp 10.0.0.7:443: connection refused")
	ce := Failed(err)
	assert.Equal(t, http.StatusInternalServerError, ce.Code)
	assert.Equal(t, CauseTokenExchangeFailed, ce.Cause)
	assert.Equal(t, err, ce.Private)
	assert.NotContains(t, ce.Error(), "10.0.0.7")
}

// An IdP can put any text in "error": only a registered code is repeated.
func TestRefusalRepeatsOnlyARegisteredCode(t *testing.T) {
	ce := Refusal(http.StatusBadRequest, "zz-sentinel-user is locked", errors.New("body"))
	assert.NotContains(t, ce.Error(), "zz-sentinel")
	assert.NotContains(t, ce.Private.Error(), "zz-sentinel")
	assert.Equal(t, "invalid_grant", ErrorCode("invalid_grant"))
}
