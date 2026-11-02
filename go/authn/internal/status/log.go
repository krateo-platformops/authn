package status

import (
	"net/http"

	"github.com/rs/zerolog"
)

// LogFailure starts the log event for a request answered with FromError(err).
// Its level follows the status code, which says whose failure it is:
//   - below 500 (a refusal of the caller: 401, 403): warn. The caller can't
//     fix authn, and authn has nothing to fix;
//   - 500 and above, or an error with no cause (FromError answers it with a
//     500): error. authn, or one of its dependencies, failed.
//
// The event carries the error, the code and, when known, the cause.
func LogFailure(log zerolog.Logger, err error) *zerolog.Event {
	st := FromError(err)

	ev := log.Error()
	if st.Code < http.StatusInternalServerError {
		ev = log.Warn()
	}
	ev = ev.Err(err).Int("code", st.Code)
	if st.Details != nil && len(st.Details.Causes) > 0 {
		ev = ev.Str("cause", string(st.Details.Causes[0].Type))
	}
	return ev
}
