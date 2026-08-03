package encode

import (
	"encoding/json"
	"net/http"

	"github.com/krateo-platformops/authn/internal/status"
)

func Unauthorized(w http.ResponseWriter, err error) error {
	return Failure(w, status.New(http.StatusUnauthorized, err))
}

func InternalError(w http.ResponseWriter, err error) error {
	return Failure(w, status.New(http.StatusInternalServerError, err))
}

func BadRequest(w http.ResponseWriter, err error) error {
	return Failure(w, status.New(http.StatusBadRequest, err))
}

func MethodNotAllowed(w http.ResponseWriter, err error) error {
	return Failure(w, status.New(http.StatusMethodNotAllowed, err))
}

func NotFound(w http.ResponseWriter, err error) error {
	return Failure(w, status.New(http.StatusNotFound, err))
}

func Forbidden(w http.ResponseWriter, err error) error {
	return Failure(w, status.New(http.StatusForbidden, err))
}

func ExpectationFailed(w http.ResponseWriter, err error) error {
	return Failure(w, status.New(http.StatusExpectationFailed, err))
}

func Failure(w http.ResponseWriter, status status.Status) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status.Code)
	return json.NewEncoder(w).Encode(&status)
}
