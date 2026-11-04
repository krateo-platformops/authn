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
