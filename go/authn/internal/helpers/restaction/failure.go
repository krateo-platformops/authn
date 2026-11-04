package restaction

import (
	"errors"
	"fmt"

	"github.com/krateo-platformops/authn/internal/status"
)

// CauseRESTActionFailed: the RESTAction that completes the identity could not
// be resolved, or its answer isn't a usable identity (500). Shared by the oidc
// and oauth logins.
const CauseRESTActionFailed status.CauseType = "RESTActionFailed"

// Failed is a RESTAction failure. The caller is told what failed and, when
// snowplow answered, its status and reason; snowplow's message and any
// transport error, which may name stage endpoints, go to the log only.
func Failed(err error) status.CauseError {
	var se *SnowplowError
	public := errors.New("the RESTAction could not be resolved")
	if errors.As(err, &se) {
		public = fmt.Errorf("the RESTAction could not be resolved: snowplow answered %d %s", se.Code, se.Reason)
	}
	return status.CauseError{Code: 500, Cause: CauseRESTActionFailed, Err: public, Private: err}
}
