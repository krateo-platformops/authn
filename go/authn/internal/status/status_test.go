package status

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Only a 2xx says Success. A code without a reason of its own, such as LDAP's
// 300 AmbiguousUser, is still a Failure.
func TestNewSaysFailureForEveryNon2xx(t *testing.T) {
	for _, code := range []int{http.StatusMultipleChoices, http.StatusBadRequest, http.StatusUnauthorized,
		http.StatusForbidden, http.StatusNotFound, http.StatusTeapot, http.StatusInternalServerError, http.StatusBadGateway} {
		assert.Equal(t, StatusFailure, New(code, errors.New("x")).Status, code)
	}
	assert.Equal(t, StatusSuccess, New(http.StatusOK, nil).Status)

	assert.Equal(t, StatusReasonBadRequest, New(http.StatusBadRequest, nil).Reason)
}

func TestBadRequest(t *testing.T) {
	st := FromError(BadRequest(CauseMissingConfigName, errors.New("name must be specified")))
	assert.Equal(t, http.StatusBadRequest, st.Code)
	assert.Equal(t, StatusFailure, st.Status)
	assert.Equal(t, StatusReasonBadRequest, st.Reason)
	assert.Equal(t, CauseMissingConfigName, st.Details.Causes[0].Type)
}

// A credential the issuer refused is answered with the issuer's own code and
// cause: wrapping it as IssuanceFailed would turn a refusal into a 500. Any
// other issuance error is IssuanceFailed.
func TestIssueFailureKeepsTheIssuersRefusal(t *testing.T) {
	refused := Refused(CauseUsernameUnavailable, errors.New(`the username isn't available to this identity`))
	st := FromError(IssueFailure("clientconfig", refused))
	assert.Equal(t, http.StatusForbidden, st.Code)
	assert.Equal(t, CauseUsernameUnavailable, st.Details.Causes[0].Type)

	st = FromError(IssueFailure("clientconfig", errors.New("csr timeout")))
	assert.Equal(t, http.StatusInternalServerError, st.Code)
	assert.Equal(t, CauseIssuanceFailed, st.Details.Causes[0].Type)
	assert.Contains(t, st.Message, "issuing clientconfig: csr timeout")
}
