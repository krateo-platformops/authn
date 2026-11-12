// Package kerr gives an error from the cluster, or from the network on the
// way to it, a text that names no object and carries no text authn didn't
// write.
//
// The apiserver names the object in its errors (`secrets "alice-clientconfig"
// not found`, `users.basic.authn.krateo.io "alice" is forbidden`), an admission
// webhook may answer any text at all, even as a Status's reason, and client-go
// adds the request URL, which names the object too. An object named after a
// user names the user, and authn's log lines carry no identity: the audit
// record, joined by session.id, is where identity lives. So where authn reads
// or writes an identity-bearing object (a session Secret, a basic User or its
// password Secret, a ServiceAccount mapping, a CSR), it wraps the error with
// Wrap, or describes it itself with Described.
//
// The wrapped error still is the original to errors.Is and errors.As:
// apierrors.IsNotFound, IsAlreadyExists and the apiserver's status code
// (errors.As(err, &apierrors.APIStatus)) work through it.
package kerr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Error is err with an identity-free text.
type Error struct {
	text string
	err  error
}

func (e *Error) Error() string { return e.text }
func (e *Error) Unwrap() error { return e.err }

// Wrap returns err, nil when err is nil, with the text "<op>: <reason>
// (<code>)" for an apiserver answer, "<op>: <transport cause>" for a request
// that got no answer (Transport), and "<op>: request failed" for anything
// else. None of err's own text is kept.
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{text: op + ": " + describe(err), err: err}
}

// Described returns err, nil when err is nil, with text as its whole text:
// for an error authn has classified itself (a CSR denied, deleted, replaced).
func Described(text string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{text: text, err: err}
}

// reasons are the StatusReasons Kubernetes defines. Any other reason is an
// admission webhook's free text, and is never repeated.
var reasons = map[metav1.StatusReason]bool{
	metav1.StatusReasonUnauthorized: true, metav1.StatusReasonForbidden: true, metav1.StatusReasonNotFound: true,
	metav1.StatusReasonAlreadyExists: true, metav1.StatusReasonConflict: true, metav1.StatusReasonGone: true,
	metav1.StatusReasonInvalid: true, metav1.StatusReasonServerTimeout: true, metav1.StatusReasonStoreReadError: true,
	metav1.StatusReasonTimeout: true, metav1.StatusReasonTooManyRequests: true, metav1.StatusReasonBadRequest: true,
	metav1.StatusReasonMethodNotAllowed: true, metav1.StatusReasonNotAcceptable: true,
	metav1.StatusReasonRequestEntityTooLarge: true, metav1.StatusReasonUnsupportedMediaType: true,
	metav1.StatusReasonInternalError: true, metav1.StatusReasonExpired: true, metav1.StatusReasonServiceUnavailable: true,
}

func describe(err error) string {
	var st apierrors.APIStatus
	if errors.As(err, &st) {
		s := st.Status()
		reason := string(s.Reason)
		if !reasons[s.Reason] {
			reason = http.StatusText(int(s.Code))
		}
		if reason == "" {
			reason = "Unknown"
		}
		return fmt.Sprintf("%s (%d)", reason, s.Code)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return Transport(err)
	}
	return "request failed"
}

// Transport describes a request that got no answer by the kind of its
// innermost cause, never by its text: a URL, at any depth, names the object
// asked for.
func Transport(err error) string {
	var (
		op   *net.OpError
		dns  *net.DNSError
		errn syscall.Errno
		unk  x509.UnknownAuthorityError
		host x509.HostnameError
		inv  x509.CertificateInvalidError
		tv   *tls.CertificateVerificationError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "the request timed out"
	case errors.Is(err, context.Canceled):
		return "the request was canceled"
	case errors.As(err, &dns):
		return "the host name could not be resolved"
	case errors.As(err, &unk), errors.As(err, &host), errors.As(err, &inv), errors.As(err, &tv):
		return "the server's TLS certificate was not accepted"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "the connection closed before an answer"
	case errors.As(err, &op):
		if op.Timeout() {
			return op.Op + ": timed out"
		}
		if errors.As(err, &errn) {
			return op.Op + ": " + errn.Error()
		}
		return op.Op + " failed"
	}
	return "the request failed in transport"
}
