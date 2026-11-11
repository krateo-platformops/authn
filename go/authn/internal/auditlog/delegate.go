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

// DelegationDenial is why /delegate refused an authenticated actor, as the
// record's schema denial reason. A refusal the schema has no reason for yet
// (the subject token's, until audit v0.6.1) is NoDelegationDenial.
type DelegationDenial string

const (
	// NoDelegationDenial: the outcome isn't denied, or the schema declares no
	// reason for the refusal.
	NoDelegationDenial DelegationDenial = ""
	// DelegationNotAllowed: the actor's mapping doesn't allow delegation.
	DelegationNotAllowed DelegationDenial = audit.DenialReasonDelegationNotAllowed
	// DelegationTooDeep: the actor chain would exceed the mapping's depth bound.
	DelegationTooDeep DelegationDenial = audit.DenialReasonDelegationTooDeep
)

// Delegation records one /delegate decision about an authenticated actor
// (AUDIT-4): a delegated token issued, refused (the actor's mapping doesn't
// allow delegation, the subject token is refused, or the chain would be too
// deep) or failed. The record is the issuance of a credential, shaped as
// Kubernetes' own (TokenRequest): verb create on the actor's ServiceAccount
// mapping, subresource token. The mapping is what an administrator edits to
// revoke delegation. authn issues the token itself, so no authority answers and
// the record carries no status code; the mapping's lookup is a read and gets no
// record (AUDIT-4 lead, 2026-11-11).
//
// subject is the person the token acts for, and chain the actor chain the token
// carries (or would have), outermost first; both are nil when the refusal came
// before the subject token was read. why is the denial reason, written on a
// denied record only.
func (r *Recorder) Delegation(req *http.Request, actor *sav1alpha1.ServiceAccount, principal jwtutil.Principal, subject *jwtutil.UserInfo, chain *jwtutil.Actor, outcome string, why DelegationDenial) {
	if r == nil || r.req == nil || actor == nil {
		return
	}
	ctx := req.Context()
	ev := audit.Event{
		UserName:   actor.Name,
		Action:     ActionDelegate,
		Outcome:    outcome,
		Verb:       "create",
		HTTPMethod: http.MethodPost,
		UserRoles:  actor.Spec.Groups,

		Namespace:             actor.Namespace,
		Group:                 sav1alpha1.Group,
		Version:               sav1alpha1.Version,
		Resource:              "serviceaccounts",
		Subresource:           "token",
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
		ev.DenialReason = string(why)
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
	r.request(req, &ev, nil) // /delegate reads its form from the body only
	r.req.Emit(ctx, ev)
}
