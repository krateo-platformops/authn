package auditlog

import (
	"net/http"

	"github.com/krateo-platformops/audit"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/plumbing/jwtutil"
)

// The /delegate record bodies.
const (
	msgDelegated     = "delegated token issued"
	msgDelegateDeny  = "delegation refused"
	msgDelegateError = "delegation failed"
)

// Delegation records one /delegate decision about an authenticated actor
// (AUDIT-4): a token issued, refused (the actor's mapping doesn't allow
// delegation, or the chain would be too deep) or failed. The target is the
// actor's ServiceAccount mapping, the object an administrator edits to revoke
// delegation; authn read it (get) and the apiserver answered.
//
// subject is the person the token acts for, and chain the actor chain the token
// carries (or would have), outermost first; both are nil when the refusal came
// before the subject token was read.
func (r *Recorder) Delegation(req *http.Request, actor *sav1alpha1.ServiceAccount, principal jwtutil.Principal, subject *jwtutil.UserInfo, chain *jwtutil.Actor, outcome string) {
	if r == nil || r.req == nil || actor == nil {
		return
	}
	ctx := req.Context()
	ev := audit.Event{
		UserName:   actor.Name,
		Action:     ActionDelegate,
		Outcome:    outcome,
		Verb:       "get",
		HTTPMethod: http.MethodGet,
		// The mapping's read was answered: Authenticate found it.
		StatusCode: http.StatusOK,

		Namespace:             actor.Namespace,
		Group:                 sav1alpha1.Group,
		Version:               sav1alpha1.Version,
		Resource:              "serviceaccounts",
		Kind:                  sav1alpha1.ServiceAccountKind,
		ObjectName:            actor.Name,
		ObjectUID:             string(actor.UID),
		ObjectResourceVersion: actor.ResourceVersion,
		ObjectGeneration:      actor.Generation,
	}
	switch outcome {
	case audit.OutcomeSuccess:
		ev.Message = msgDelegated
	case audit.OutcomeDenied:
		ev.Message = msgDelegateDeny
	default:
		ev.Message = msgDelegateError
	}
	if c, ok := audit.ParseClaim(string(principal)); ok {
		ev.ActorClass = c
	}
	if subject != nil {
		ev.OnBehalfOf = subject.Username
		for a := chain; a != nil; a = a.Act {
			c, _ := audit.ParseClaim(string(a.Principal))
			ev.Delegation = append(ev.Delegation, audit.Link{Class: c, Subject: a.Sub})
		}
		c, _ := audit.ParseClaim(string(subject.Principal))
		ev.Delegation = append(ev.Delegation, audit.Link{Class: c, Subject: subject.Username})
	}
	ev.Preview = r.previewOf(ctx, actor.Namespace)
	r.request(req, &ev, false)
	r.req.Emit(ctx, ev)
}
