// Package usernames serves POST /usernames/check: whether a username could
// be given to a new identity, for an in-cluster service that opted in (an
// access-request controller). It runs the sign-in name guard's reads and
// issues nothing.
//
// It is served on authn's INTERNAL listener only, never on the public one:
// whether a name is held is decided in-cluster, never on a public surface, so
// nobody can enumerate who exists (docs/behavior.md).
package usernames

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/routes/auth/serviceaccount"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

// Path is the route's path, on the internal listener.
const Path = "/usernames/check"

// maxBody bounds the request body: one username.
const maxBody = 4 << 10

// Causes of a failed check besides the caller's, which are
// /serviceaccount/login's (serviceaccount.Cause*).
const (
	CauseInvalidRequestBody                       = status.CauseInvalidRequestBody // 400
	CauseMissingUsername         status.CauseType = "MissingUsername"              // 400
	CauseUsernameCheckNotAllowed status.CauseType = "UsernameCheckNotAllowed"      // 403
	CauseUsernameCheckFailed     status.CauseType = "UsernameCheckFailed"          // 503
)

// Request is the body of POST /usernames/check.
type Request struct {
	// Username is the name to check. It must be present; an empty one is
	// checked, and is invalid.
	Username *string `json:"username"`
}

// Response is the 200 answer.
type Response struct {
	Available bool `json:"available"`
	// Reason is why the name is unavailable, one of kubeconfig.Unavailables;
	// omitted when it is available.
	Reason kubeconfig.Unavailable `json:"reason,omitempty"`
}

// Options configures the route.
type Options struct {
	// Audience the caller's projected ServiceAccount token must carry.
	Audience string
	// Lookup answers the name guard's questions; nil uses the cluster's.
	Lookup kubeconfig.NameLookup
}

// Route returns POST /usernames/check.
func Route(rc *rest.Config, opts Options) routes.Route {
	return &route{rc: rc, opts: opts}
}

type route struct {
	rc   *rest.Config
	opts Options
}

func (r *route) Name() string    { return "usernames.check" }
func (r *route) Pattern() string { return Path }
func (r *route) Method() string  { return http.MethodPost }

func (r *route) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context())
		fail := func(err error, msg string) {
			status.LogFailure(*log, err).Msg(msg)
			encode.Failure(wri, status.FromError(err))
		}

		token, ok := serviceaccount.BearerToken(req)
		if !ok {
			wri.Header().Set("WWW-Authenticate", `Bearer realm="krateo"`)
			err := errors.New("the caller's ServiceAccount token must be sent as Authorization: Bearer")
			encode.Failure(wri, status.New(http.StatusUnauthorized, err).
				WithCause(serviceaccount.CauseMissingBearer, err.Error()))
			return
		}

		caller, _, err := serviceaccount.Authenticate(req.Context(), r.rc, r.opts.Audience, token)
		if err != nil {
			fail(err, "username check caller not authenticated")
			return
		}
		if !allowed(caller) {
			fail(status.Refused(CauseUsernameCheckNotAllowed,
				fmt.Errorf("the ServiceAccount mapping %s doesn't set spec.usernameCheck.allowed", caller.Name)),
				"username check refused")
			return
		}

		username, err := readUsername(req)
		if err != nil {
			fail(err, "username check request refused")
			return
		}

		lookup := r.opts.Lookup
		if lookup == nil {
			if lookup, err = kubeconfig.NewNameLookup(r.rc); err != nil {
				fail(checkFailed(err), "username check failed")
				return
			}
		}
		why, err := kubeconfig.CheckUsername(req.Context(), lookup, username)
		if err != nil {
			// Fail closed: the caller can't know, so it treats the name as
			// unavailable and retries.
			fail(checkFailed(fmt.Errorf("checking username %q: %w", username, err)), "username check failed")
			return
		}

		log.Info().Str("caller", caller.Name).Bool("available", why == "").Str("reason", string(why)).
			Msg("username checked")
		wri.Header().Set("Content-Type", "application/json")
		wri.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(wri).Encode(Response{Available: why == "", Reason: why})
	}
}

// checkFailed is a check authn could not complete (503): fail closed, the
// caller treats the name as unavailable and retries.
func checkFailed(err error) status.CauseError {
	return status.CauseError{Code: http.StatusServiceUnavailable, Cause: CauseUsernameCheckFailed, Err: err}
}

// allowed reports whether the caller's mapping opted in to the check.
func allowed(m *sav1alpha1.ServiceAccount) bool {
	return m != nil && m.Spec.UsernameCheck != nil && m.Spec.UsernameCheck.Allowed
}

// readUsername reads the request's username: a JSON body with the field
// present, possibly empty.
func readUsername(req *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return "", status.BadRequest(CauseInvalidRequestBody, errors.New("the body must be a JSON object of at most 4 KiB"))
	}
	var r Request
	if err := json.Unmarshal(body, &r); err != nil {
		return "", status.BadRequest(CauseInvalidRequestBody, fmt.Errorf("the body is not JSON: %w", err))
	}
	if r.Username == nil {
		return "", status.BadRequest(CauseMissingUsername, errors.New(`the body must carry "username"`))
	}
	return *r.Username, nil
}
