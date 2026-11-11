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
)

// The controller record bodies.
const (
	msgSwept       = "expired credential deleted"
	msgSweepError  = "expired credential not deleted"
	msgCertStored  = "service credential stored"
	msgCertFailure = "service credential not stored"
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

// ServiceCertIssued records the write of authn's own certificate to its
// clientconfig Secret: the request that stored it, or failed to (plumbing
// endpoints.StoreWritten). A renewal that failed before the Secret was written
// (the CSR) sends nothing for it and is not recorded.
func (c *Controller) ServiceCertIssued(ctx context.Context, ref SecretRef, verb string, code int, err error) {
	if c == nil || c.e == nil || verb == "" {
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
		ev.Outcome, ev.Message = audit.OutcomeFailure, msgCertFailure
		if ev.StatusCode == 0 {
			ev.StatusCode = statusCodeOf(err)
		}
	}
	ev.Preview = previewOf(c.preview, ctx, ref.Namespace)
	c.e.Emit(ctx, ev)
}
