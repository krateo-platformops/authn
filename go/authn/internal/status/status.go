package status

import "net/http"

// Values of Status.Status
const (
	StatusSuccess = "Success"
	StatusFailure = "Failure"
)

// StatusReason is an enumeration of possible failure causes.  Each StatusReason
// must map to a single HTTP status code, but multiple reasons may map
// to the same HTTP status code.
type StatusReason string

const (
	// StatusReasonUnknown means the server has declined to indicate a specific reason.
	// Status code 500.
	StatusReasonUnknown StatusReason = ""

	// StatusReasonUnauthorized means the server can be reached and understood the request, but requires
	// the user to present appropriate authorization credentials.
	// Status code 401
	StatusReasonUnauthorized StatusReason = "Unauthorized"

	// StatusReasonForbidden means the server can be reached and understood the request, but refuses
	// to take any further action.
	// Status code 403
	StatusReasonForbidden StatusReason = "Forbidden"

	// StatusReasonNotFound means one or more resources required for this operation
	// could not be found.
	// Status code 404
	StatusReasonNotFound StatusReason = "NotFound"

	// StatusReasonConflict means the requested operation cannot be completed
	// due to a conflict in the operation.
	// Status code 409
	StatusReasonConflict StatusReason = "Conflict"

	// StatusReasonGone means the item is no longer available at the server and no
	// forwarding address is known.
	// Status code 410
	StatusReasonGone StatusReason = "Gone"

	// StatusReasonInvalid means the requested create or update operation cannot be
	// completed due to invalid data provided as part of the request.
	// Status code 422
	StatusReasonInvalid StatusReason = "Invalid"

	// StatusReasonTimeout means that the request could not be completed within the given time.
	// Status code 504
	StatusReasonTimeout StatusReason = "Timeout"

	// StatusReasonTooManyRequests means the server experienced too many requests within a
	// given window and that the client must wait to perform the action again.
	// Status code 429
	StatusReasonTooManyRequests StatusReason = "TooManyRequests"

	// StatusReasonBadRequest means that the request itself was invalid, because the request
	// doesn't make any sense.
	// Status code 400
	StatusReasonBadRequest StatusReason = "BadRequest"

	// StatusReasonMethodNotAllowed means that the action the client attempted to perform not supported.
	// Status code 405
	StatusReasonMethodNotAllowed StatusReason = "MethodNotAllowed"

	// StatusReasonNotAcceptable means that the accept types indicated by the client were not acceptable
	// to the server.
	// Status code 406
	StatusReasonNotAcceptable StatusReason = "NotAcceptable"

	// StatusReasonRequestEntityTooLarge means that the request entity is too large.
	// Status code 413
	StatusReasonRequestEntityTooLarge StatusReason = "RequestEntityTooLarge"

	// StatusReasonUnsupportedMediaType means that the content type sent by the client is not acceptable.
	// Status code 415
	StatusReasonUnsupportedMediaType StatusReason = "UnsupportedMediaType"

	// StatusReasonInternalError indicates that an internal error occurred.
	// Status code 500
	StatusReasonInternalError StatusReason = "InternalError"

	// StatusReasonServiceUnavailable means that the request itself was valid,
	// but the requested service is unavailable at this time.
	// Status code 503
	StatusReasonServiceUnavailable StatusReason = "ServiceUnavailable"
)

// Status is a return value for calls that don't return other objects.
type Status struct {
	Kind       string `json:"kind,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`

	// Status of the operation.
	// One of: "Success" or "Failure".
	Status string `json:"status,omitempty"`
	// A human-readable description of the status of this operation.
	Message string `json:"message,omitempty"`
	// A machine-readable description of why this operation is in the
	// "Failure" status. If this value is empty there
	// is no information available. A Reason clarifies an HTTP status
	// code but does not override it.
	Reason StatusReason `json:"reason,omitempty"`
	// Suggested HTTP return code for this status, 0 if not set.
	Code int `json:"code,omitempty"`
}

func New(code int, err error) Status {
	res := Status{
		Kind:       "Status",
		APIVersion: "v1",
		Code:       code,
	}

	if err != nil {
		res.Message = err.Error()
	}

	switch code {
	case http.StatusUnauthorized:
		res.Status = StatusFailure
		res.Reason = StatusReasonUnauthorized
	case http.StatusForbidden:
		res.Status = StatusFailure
		res.Reason = StatusReasonForbidden
	case http.StatusNotFound:
		res.Status = StatusFailure
		res.Reason = StatusReasonNotFound
	case http.StatusConflict:
		res.Status = StatusFailure
		res.Reason = StatusReasonConflict
	case http.StatusGone:
		res.Status = StatusFailure
		res.Reason = StatusReasonGone
	case http.StatusNotImplemented:
		res.Status = StatusFailure
		res.Reason = StatusReasonInvalid
	case http.StatusServiceUnavailable:
		res.Status = StatusFailure
		res.Reason = StatusReasonServiceUnavailable
	case http.StatusNotAcceptable:
		res.Status = StatusFailure
		res.Reason = StatusReasonNotAcceptable
	case http.StatusMethodNotAllowed:
		res.Status = StatusFailure
		res.Reason = StatusReasonMethodNotAllowed
	case http.StatusInternalServerError:
		res.Status = StatusFailure
		res.Reason = StatusReasonInternalError
	case http.StatusRequestEntityTooLarge:
		res.Status = StatusFailure
		res.Reason = StatusReasonRequestEntityTooLarge
	case http.StatusUnsupportedMediaType:
		res.Status = StatusFailure
		res.Reason = StatusReasonUnsupportedMediaType
	default:
		res.Status = StatusSuccess
	}

	return res
}
