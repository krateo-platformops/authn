package restaction

import (
	"errors"
	"fmt"

	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/status"
)

// CauseRESTActionFailed: the RESTAction that completes the identity could not
// be resolved, or its answer isn't a usable identity (500). Shared by the oidc
// and oauth logins.
const CauseRESTActionFailed status.CauseType = "RESTActionFailed"

// Failed is a RESTAction failure. The caller is told what failed and, when
// snowplow answered, its status and reason; a transport error, which may name
// stage endpoints, goes to the log only. snowplow's message goes nowhere: it
// can quote the RESTAction's data, which is the user's identity.
func Failed(err error) status.CauseError {
	var se *SnowplowError
	public := errors.New("the RESTAction could not be resolved")
	private := err
	if errors.As(err, &se) {
		public = fmt.Errorf("the RESTAction could not be resolved: %s", se.Error())
		private = kerr.Described(se.Error(), err)
	}
	return status.CauseError{Code: 500, Cause: CauseRESTActionFailed, Err: public, Private: private}
}
