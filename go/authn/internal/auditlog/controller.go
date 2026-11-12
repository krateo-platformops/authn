package auditlog

import (
	"context"
	"errors"
	"net/http"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/log"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// The controller krateo.action literals.
const (
	// ActionStepUpExpired: the step-up sweep deleted an expired step-up credential.
	ActionStepUpExpired = "authn.stepup.expired"
	// ActionServiceCertIssued: authn issued (or renewed) its own client
	// certificate and stored it in its clientconfig Secret.
	ActionServiceCertIssued = "authn.servicecert.issued"
	// ActionIdentityBackfilled: at startup, authn stamped the authorization-
	// bearing identity annotations (strategy, groups) or the owner of a
	// credential Secret written before it recorded them.
	ActionIdentityBackfilled = "authn.identity.backfilled"
	// ActionServiceIdentityAnnotated: authn brought the authorization-bearing
	// identity annotations of its own credential in line with its certificate.
	ActionServiceIdentityAnnotated = "authn.servicecert.annotated"
	// ActionIdentityInconsistent: at startup, with exact naming on (authn#140, authn#144),
	// the backfill found an identity key (the username annotation, the
	// principal or username-label label) on a credential Secret with a value
	// other than its certificate proves, and left it as found.
	ActionIdentityInconsistent = "authn.identity.inconsistent"
)

// The controller record bodies.
const (
	msgSwept       = "expired credential deleted"
	msgSweepError  = "expired credential not deleted"
	msgCertStored  = "service credential stored"
	msgCertFailure = "service credential not stored"
	msgIdentity    = "credential identity recorded"
	msgIdentityErr = "credential identity not recorded"
	msgIdentityOdd = "credential identity left as found"
)

// Controller writes the records of authn's own background credential writes
// (AUDIT-4's named exception to installer#413 condition 1): no request drives
// them, so the actor is authn's ServiceAccount. A nil Controller, or one built
// without a LoggerProvider, writes nothing.
type Controller struct {
	e       *audit.Emitter
	preview PreviewSource
}

// NewController builds the Controller. serviceAccount is authn's own,
// system:serviceaccount:<namespace>:<name>.
func NewController(lp log.LoggerProvider, serviceAccount string, preview PreviewSource) *Controller {
	if lp == nil {
		return &Controller{}
	}
	return &Controller{
		e: audit.New(lp.Logger(ScopeController),
			audit.WithWriter(audit.WriterController),
			audit.WithActor(serviceAccount, audit.ClassController)),
		preview: preview,
	}
}

// SecretRef names a Secret a background write targeted.
type SecretRef struct {
	Namespace, Name, UID, ResourceVersion string
}

// StepUpExpired records the sweep's delete of an expired step-up Secret. code
// is the apiserver's HTTP status (0 when not known, and then omitted rather
// than assumed), err the delete's error.
func (c *Controller) StepUpExpired(ctx context.Context, ref SecretRef, code int, err error) {
	if c == nil || c.e == nil {
		return
	}
	ev := audit.Event{
		Action:     ActionStepUpExpired,
		Verb:       "delete",
		HTTPMethod: http.MethodDelete,
		Outcome:    audit.OutcomeSuccess,
		Message:    msgSwept,
		StatusCode: code,

		Namespace: ref.Namespace, Version: "v1", Resource: "secrets", Kind: "Secret",
		ObjectName: ref.Name, ObjectUID: ref.UID, ObjectResourceVersion: ref.ResourceVersion,
	}
	if err != nil {
		ev.Outcome, ev.Message = audit.OutcomeFailure, msgSweepError
		if ev.StatusCode == 0 {
			ev.StatusCode = statusCodeOf(err)
		}
	}
	ev.Preview = previewOf(c.preview, ctx, ref.Namespace)
	c.e.Emit(ctx, ev)
}

// statusCodeOf is the apiserver's HTTP status in err, 0 when it carries none.
func statusCodeOf(err error) int {
	var s apierrors.APIStatus
	if errors.As(err, &s) {
		return int(s.Status().Code)
	}
	return 0
}

// ServiceCertIssued records one issue or renewal of authn's own certificate:
// the write of its clientconfig Secret, as sent (plumbing
// endpoints.StoreWritten), or, when it failed before that write (at the CSR),
// the write it would have sent, as a failure with no status code (AUDIT-4
// ruling 4, as for a login). An empty verb, when even that couldn't be told, is
// omitted and the record marked incomplete, never guessed.
func (c *Controller) ServiceCertIssued(ctx context.Context, ref SecretRef, verb string, code int, err error) {
	if c == nil || c.e == nil {
		return
	}
	ev := audit.Event{
		Action:     ActionServiceCertIssued,
		Verb:       verb,
		HTTPMethod: methodOf(verb),
		Outcome:    audit.OutcomeSuccess,
		Message:    msgCertStored,
		StatusCode: code,

		Namespace: ref.Namespace, Version: "v1", Resource: "secrets", Kind: "Secret",
		ObjectName: ref.Name, ObjectUID: ref.UID, ObjectResourceVersion: ref.ResourceVersion,
	}
	if err != nil {
		// code is the Secret write's own answer (StoreWritten), or 0 when no
		// request was sent for it. err may be an earlier step's (the CSR's), so
		// its status is not the Secret's and is never borrowed.
		ev.Outcome, ev.Message = audit.OutcomeFailure, msgCertFailure
	}
	ev.Preview = previewOf(c.preview, ctx, ref.Namespace)
	c.e.Emit(ctx, ev)
}

// IdentityWritten records a background write of a credential Secret's
// authorization-bearing identity (audit.AuthorizationAnnotations, or its
// owner): action is ActionIdentityBackfilled or ActionServiceIdentityAnnotated.
// The write is a full update (PUT), so verb update and the apiserver's answer.
func (c *Controller) IdentityWritten(ctx context.Context, action string, ref SecretRef, code int, err error) {
	if c == nil || c.e == nil {
		return
	}
	ev := audit.Event{
		Action:     action,
		Verb:       "update",
		HTTPMethod: http.MethodPut,
		Outcome:    audit.OutcomeSuccess,
		Message:    msgIdentity,
		StatusCode: code,

		Namespace: ref.Namespace, Version: "v1", Resource: "secrets", Kind: "Secret",
		ObjectName: ref.Name, ObjectUID: ref.UID, ObjectResourceVersion: ref.ResourceVersion,
	}
	if err != nil {
		ev.Outcome, ev.Message = audit.OutcomeFailure, msgIdentityErr
	}
	ev.Preview = previewOf(c.preview, ctx, ref.Namespace)
	c.e.Emit(ctx, ev)
}

// IdentityInconsistent records that the backfill declined to overwrite an
// identity key a credential Secret already holds with another value than its
// certificate proves (authn#144): rewriting a label a tenant policy already
// generated from would point it at a second tenant. Nothing was written, so
// the record is denied, naming the update it declined to send, with no status
// code and no denial reason: the controller writer declares none that fits
// (audit schema v1). The record names the Secret, never the values.
func (c *Controller) IdentityInconsistent(ctx context.Context, ref SecretRef) {
	if c == nil || c.e == nil {
		return
	}
	ev := audit.Event{
		Action:     ActionIdentityInconsistent,
		Verb:       "update",
		HTTPMethod: http.MethodPut,
		Outcome:    audit.OutcomeDenied,
		Message:    msgIdentityOdd,

		Namespace: ref.Namespace, Version: "v1", Resource: "secrets", Kind: "Secret",
		ObjectName: ref.Name,
	}
	ev.Preview = previewOf(c.preview, ctx, ref.Namespace)
	c.e.Emit(ctx, ev)
}
