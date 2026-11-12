package auditlog

import (
	"net/http"

	"github.com/krateo-platformops/audit"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
)

// MappingDenial is why authn refused a caller whose ServiceAccount token the
// TokenReview verified, at the mapping lookup that names its identity, as the
// record's schema denial reason (authn#132).
type MappingDenial string

const (
	// NoMappingDenial: the outcome isn't denied.
	NoMappingDenial MappingDenial = ""
	// MappingMissing: no ServiceAccount mapping names the caller's
	// ServiceAccount (the allowlist doesn't hold it).
	MappingMissing MappingDenial = audit.DenialReasonNoMapping
	// MappingAmbiguous: more than one mapping names it.
	MappingAmbiguous MappingDenial = audit.DenialReasonAmbiguousMapping
	// NotAServiceAccount: the TokenReview verified the token, but its user is
	// not a Kubernetes ServiceAccount (a person's token, for one).
	NotAServiceAccount MappingDenial = audit.DenialReasonNotAServiceAccount
)

// Unmapped records a caller the TokenReview verified that authn refused, or
// failed, at the mapping lookup (authn#132): on /serviceaccount/login
// (LoginAction(StrategyServiceAccount)), on /delegate (ActionDelegate) and on
// /usernames/check (ActionUsernameCheck).
//
// user is the TokenReview's username, the identity that was verified. No
// mapping can be named (none, or more than one, names it, or the lookup
// failed), so the record names the mapping resource in authn's namespace
// without a name, and no verb, as a name_missing record names the Secret
// resource. why is the reason on a denied record. statusCode is the
// apiserver's answer to the failed lookup, 0 when none came; a denied record
// carries none, since authn refused without asking.
func (r *Recorder) Unmapped(req *http.Request, action, user, outcome string, why MappingDenial, statusCode int) {
	if r == nil || r.req == nil || user == "" {
		return
	}
	ctx := req.Context()
	ev := audit.Event{
		UserName: user,
		Action:   action,
		Outcome:  outcome,
		Group:    sav1alpha1.Group,
		Version:  sav1alpha1.Version,
		Resource: "serviceaccounts",
		Kind:     sav1alpha1.ServiceAccountKind,
	}
	if ns, err := util.GetOperatorNamespace(); err == nil {
		ev.Namespace = ns
	}
	denied := outcome == audit.OutcomeDenied
	ev.Message = unmappedMessage(action, denied)
	if denied {
		ev.DenialReason = string(why)
	} else if statusCode > 0 {
		ev.StatusCode = statusCode
	}
	ev.Preview = r.previewOf(ctx, ev.Namespace)
	r.request(req, &ev, queryParams[action])
	r.req.Emit(ctx, ev)
}

// unmappedMessage is the action's own body for a refusal or a failure, from
// the closed set its other records use.
func unmappedMessage(action string, denied bool) string {
	switch {
	case action == ActionDelegate && denied:
		return msgDelegateDeny
	case action == ActionDelegate:
		return msgDelegateError
	case action == ActionUsernameCheck && denied:
		return msgCheckRefused
	case action == ActionUsernameCheck:
		return msgCheckFailed
	case denied:
		return msgRefused
	default:
		return msgFailed
	}
}
