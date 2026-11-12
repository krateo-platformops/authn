package restaction

import (
	"errors"
	"fmt"

	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/status"
)

// The causes of a RESTAction that doesn't complete the identity (500), shared
// by the oidc and oauth logins. They differ in what the caller should do, so
// a client can tell them apart from the cause alone:
const (
	// CauseRESTActionFailed: the RESTAction could not be resolved: snowplow
	// answered an error, or nothing answered. Usually transient: retry later.
	CauseRESTActionFailed status.CauseType = "RESTActionFailed"
	// CauseRESTActionIdentityInvalid: the RESTAction was resolved, but its
	// answer isn't a usable identity (it lacks name or subject, or a field
	// has the wrong type), or the config names no RESTAction at all. An
	// answer that isn't JSON is snowplow's failure: CauseRESTActionFailed. A configuration
	// problem: retrying won't help, an administrator has to fix it.
	CauseRESTActionIdentityInvalid status.CauseType = "RESTActionIdentityInvalid"
)

// IdentityInvalid is a RESTAction that was resolved but identifies no one,
// or a config that names none (CauseRESTActionIdentityInvalid).
func IdentityInvalid(err error) status.CauseError {
	return status.CauseError{Code: 500, Cause: CauseRESTActionIdentityInvalid, Err: err}
}

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
