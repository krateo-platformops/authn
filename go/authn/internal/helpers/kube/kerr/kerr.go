// Package kerr gives an apiserver error a text that names no object.
//
// The apiserver names the object in its errors (`secrets "alice-clientconfig"
// not found`, `users.basic.authn.krateo.io "alice" is forbidden`), and so does
// client-go (the request URL of a failed call, a name it refuses to send). An
// object named after a user names the user, and authn's log lines carry no
// identity: the audit record, joined by session.id, is where identity lives.
// So where authn reads or writes an identity-bearing object (a session Secret,
// a basic User or its password Secret, a ServiceAccount mapping, a CSR), it
// wraps the error with Wrap or Redact.
//
// The wrapped error still is the original to errors.Is and errors.As:
// apierrors.IsNotFound, IsAlreadyExists and the apiserver's status code
// (errors.As(err, &apierrors.APIStatus)) work through it.
package kerr

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Error is err with an identity-free text.
type Error struct {
	text string
	err  error
}

func (e *Error) Error() string { return e.text }
func (e *Error) Unwrap() error { return e.err }

// Wrap returns err, nil when err is nil, with the text "<op>: <reason>
// (<code>)" for an apiserver answer, "<op>: <cause>" for a request that got no
// answer (the URL, which names the object, is left out), and "<op>: request
// failed" for anything else, whose text may carry a name.
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{text: op + ": " + describe(err), err: err}
}

// Redact returns err, nil when err is nil, with the text "<op>: <err's text>"
// in which each of names is replaced by "<name>". It is for an error that
// isn't the apiserver's answer and whose text authn can't otherwise describe,
// such as client-go's wait for a CSR's certificate, which names the CSR.
func Redact(op string, err error, names ...string) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	for _, n := range names {
		if n != "" {
			text = strings.ReplaceAll(text, n, "<name>")
		}
	}
	return &Error{text: op + ": " + text, err: err}
}

func describe(err error) string {
	var st apierrors.APIStatus
	if errors.As(err, &st) {
		s := st.Status()
		reason := string(s.Reason)
		if reason == "" {
			reason = http.StatusText(int(s.Code))
		}
		if reason == "" {
			reason = "Unknown"
		}
		return fmt.Sprintf("%s (%d)", reason, s.Code)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + " request: " + ue.Err.Error()
	}
	return "request failed"
}
