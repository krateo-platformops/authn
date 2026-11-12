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

	"github.com/krateo-platformops/audit"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/routes/auth/serviceaccount"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	// Naming is how session Secrets are named (storage.Naming), as the
	// sign-in's name guard reads them; the zero value is the legacy naming.
	Naming storage.Naming
	// Audit records every decision about a caller the TokenReview verified
	// (AUDIT-4, authn.username.check). Nil records nothing.
	Audit *auditlog.Recorder
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

		caller, verified, err := serviceaccount.Authenticate(req.Context(), r.rc, r.opts.Audience, token)
		if err != nil {
			// A caller the TokenReview verified is recorded however it was
			// refused or failed at its mapping (authn#132).
			serviceaccount.RecordUnmapped(r.opts.Audit, req, auditlog.ActionUsernameCheck, verified)
			fail(err, "username check caller not authenticated")
			return
		}
		principal := serviceaccount.Principal(caller)
		record := func(username, outcome, result string, why auditlog.CheckDenial, code int) {
			r.opts.Audit.UsernameCheck(req, caller, principal, username, outcome, result, why, code)
		}
		if !allowed(caller) {
			// The record names the name asked about, when the body says it, so
			// a refused check joins that name's other records; the check
			// itself never runs.
			username, _ := readUsername(req)
			record(username, audit.OutcomeDenied, "", auditlog.CheckNotAllowed, 0)
			fail(status.Refused(CauseUsernameCheckNotAllowed,
				errors.New("the caller's ServiceAccount mapping doesn't set spec.usernameCheck.allowed")),
				"username check refused")
			return
		}

		username, err := readUsername(req)
		if err != nil {
			record("", audit.OutcomeDenied, "", auditlog.CheckInvalidRequest, 0)
			fail(err, "username check request refused")
			return
		}

		lookup := r.opts.Lookup
		if lookup == nil {
			if lookup, err = kubeconfig.NewNameLookup(r.rc); err != nil {
				record(username, audit.OutcomeFailure, "", auditlog.NoCheckDenial, 0)
				fail(checkFailed(kerr.Wrap("building the name lookup", err)), "username check failed")
				return
			}
		}
		why, err := kubeconfig.CheckUsernameWith(req.Context(), lookup, r.opts.Naming, username)
		if err != nil {
			// Fail closed: the caller can't know, so it treats the name as
			// unavailable and retries.
			record(username, audit.OutcomeFailure, "", auditlog.NoCheckDenial, answeredCode(err))
			// kerr keeps only the error's identity-free class, whatever the
			// lookup wrote: no log line carries the name asked about.
			fail(checkFailed(kerr.Wrap("checking the username", err)), "username check failed")
			return
		}
		record(username, audit.OutcomeSuccess, checkResult(why), auditlog.NoCheckDenial, 0)

		// No identity in the log line, the caller's or the name's: the audit
		// record carries both (Diego, 2026-11-12).
		log.Info().Bool("available", why == "").Str("reason", string(why)).Msg("username checked")
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

// checkResults is each check answer's krateo.audit.check_result, the closed
// set audit declares for authn.username.check: "" (available) and every
// kubeconfig.Unavailables value. TestEveryAnswerHasACheckResult pins it.
var checkResults = map[kubeconfig.Unavailable]string{
	"":                                audit.CheckResultAvailable,
	kubeconfig.UnavailableInvalid:     audit.CheckResultInvalid,
	kubeconfig.UnavailableReserved:    audit.CheckResultReserved,
	kubeconfig.UnavailableClaimed:     audit.CheckResultNameClaimed,
	kubeconfig.UnavailableHeldLegacy:  audit.CheckResultNameHeldLegacy,
	kubeconfig.UnavailableProvisioned: audit.CheckResultNameProvisioned,
	kubeconfig.UnavailableBound:       audit.CheckResultNameBound,
}

// checkResult is why's check_result, "" for an answer audit doesn't declare
// (which TestEveryAnswerHasACheckResult keeps from existing): a record then
// carries none rather than one Check would refuse.
func checkResult(why kubeconfig.Unavailable) string { return checkResults[why] }

// answeredCode is the apiserver's status code when it answered the failed
// lookup, 0 when nothing answered (a timeout, a refused connection): only an
// authority's answer is a record's status code.
func answeredCode(err error) int {
	var answered apierrors.APIStatus
	if errors.As(err, &answered) {
		return int(answered.Status().Code)
	}
	return 0
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
