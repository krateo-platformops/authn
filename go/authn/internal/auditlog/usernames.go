package auditlog

import (
	"net/http"

	"github.com/krateo-platformops/audit"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/krateo-platformops/plumbing/kubeutil"
)

// ActionUsernameCheck is POST /usernames/check's krateo.action: whether a
// username could be given to a new identity (audit v0.9.0).
const ActionUsernameCheck = "authn.username.check"

// The /usernames/check record bodies.
const (
	msgChecked      = "username checked"
	msgCheckRefused = "username check refused"
	msgCheckFailed  = "username check failed"
)

// CheckDenial is why /usernames/check refused a caller whose mapping it found,
// as the record's schema denial reason.
type CheckDenial string

const (
	// NoCheckDenial: the outcome isn't denied, or authn refused without a
	// reason the schema declares (a body it couldn't read).
	NoCheckDenial CheckDenial = ""
	// CheckNotAllowed: the caller's mapping doesn't set
	// spec.usernameCheck.allowed.
	CheckNotAllowed CheckDenial = audit.DenialReasonUsernameCheckNotAllowed
)

// UsernameCheck records one /usernames/check decision about a caller whose
// ServiceAccount mapping was found (AUDIT-4; snowplow's rulings, 2026-11-12):
// the check completed (success, whatever it concluded), refused (denied: the
// mapping hasn't opted in, or the body named no username) or failed (a lookup
// failed, so the caller was told nothing).
//
// The actor is the caller's mapping, of its declared class, as on /delegate.
// The record is a read, verb get, of the checked name's <username>-clientconfig
// Secret in authn's namespace: what a sign-in under that name would write, and
// what its refusals name, so one object_ref query joins a name's checks,
// refusals and logins. The verb is get on every record, since the check is a
// read whatever the name. A name whose Secret isn't its own (checkedSecret)
// names the resource without a name, as a name_missing login record does.
//
// result is the check's answer (audit.CheckResult*), on a success only.
// statusCode is the apiserver's answer to a failed lookup, 0 when none came;
// it is written on a failure only. why is the reason on a denied record.
func (r *Recorder) UsernameCheck(req *http.Request, caller *sav1alpha1.ServiceAccount, principal jwtutil.Principal, username, outcome, result string, why CheckDenial, statusCode int) {
	if r == nil || r.req == nil || caller == nil {
		return
	}
	ctx := req.Context()
	ev := audit.Event{
		UserName:  caller.Name,
		UserRoles: caller.Spec.Groups,
		Action:    ActionUsernameCheck,
		Outcome:   outcome,
		Version:   "v1",
		Resource:  "secrets",
		Kind:      "Secret",
	}
	if ns, err := util.GetOperatorNamespace(); err == nil {
		ev.Namespace = ns
	}
	// The check is a read whatever the name: unlike a nameless login, which
	// can't know whether it would have created or updated, its verb is known.
	ev.Verb, ev.HTTPMethod = "get", methodOf("get")
	ev.ObjectName = checkedSecret(username)
	if c, ok := audit.ParseClaim(string(principal)); ok {
		ev.ActorClass = c
	}
	switch outcome {
	case audit.OutcomeSuccess:
		ev.Message = msgChecked
		ev.CheckResult = result
	case audit.OutcomeDenied:
		ev.Message = msgCheckRefused
		ev.DenialReason = string(why)
	default:
		ev.Message = msgCheckFailed
		if statusCode > 0 {
			ev.StatusCode = statusCode
		}
	}
	ev.Preview = r.previewOf(ctx, ev.Namespace)
	r.request(req, &ev, nil) // the username comes in the body only
	r.req.Emit(ctx, ev)
}

// checkedSecret is the <username>-clientconfig Secret the record names, or ""
// when that Secret isn't the name's own: username is empty (absent, or a body
// authn couldn't read), or deriving the Secret's name rewrites it. The
// derivation (endpoints.SecretName) lowercases, strips what an object name
// can't hold and truncates, so Alice@Example would land on
// aliceexample-clientconfig, which can be a real user's Secret, and a query for
// that user would show checks for names that were never theirs. The condition
// is the derivation's own transform, so the two can't drift (snowplow,
// 2026-11-12). A reserved but well-formed name, such as admin, is named, so its
// checks join its sign-in refusals.
func checkedSecret(username string) string {
	if username == "" || kubeutil.MakeDNS1123Compatible(username) != username {
		return ""
	}
	return storage.ClientConfigSecretName(username)
}
