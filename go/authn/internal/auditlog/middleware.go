package auditlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"time"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
)

// Middleware prepares each request for its audit records. It stamps when the
// request was received, and it makes sure the context carries a session.id:
// the inbound W3C baggage member when it is a well-formed one (ValidSessionID),
// a minted one otherwise.
// Baggage is extracted here even with tracing off, when no otelhttp handler has
// done it. Inside, audit.RecordedMiddleware marks the Server span of a request
// that wrote a record, so observability keeps that trace whole.
//
// Place it inside the otelhttp handler, so the Server span is active.
func Middleware(next http.Handler) http.Handler {
	recorded := audit.RecordedMiddleware(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), receivedKey{}, time.Now())
		ctx = withSession(ctx, r.Header)
		recorded.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sessionIDFormat is audit's session_id format, as audit#32 declares it: 1 to
// 128 of [A-Za-z0-9._-]. A caller sets session.id, so anything else (an
// email, a name, a forged log line) could carry an identity into the audit
// record's join key and into every log line. It is replaced by
// audit.ValidSessionID once audit v0.11.0 is tagged.
var sessionIDFormat = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidSessionID reports whether s has audit's session_id format (audit#32).
// It stands in for audit.ValidSessionID until audit v0.11.0.
func ValidSessionID(s string) bool { return sessionIDFormat.MatchString(s) }

// SessionID returns ctx's session.id when it is one authn accepts. After
// Middleware, a request's always is.
func SessionID(ctx context.Context) (string, bool) {
	v := baggage.FromContext(ctx).Member(audit.BaggageSessionKey).Value()
	return v, ValidSessionID(v)
}

// withSession returns ctx with a session.id baggage member authn accepts
// (ValidSessionID): the one already in ctx, else the one in the request's
// baggage header, else a minted one, which replaces a malformed one.
func withSession(ctx context.Context, h http.Header) context.Context {
	if _, ok := SessionID(ctx); ok {
		return ctx
	}
	ctx = propagation.Baggage{}.Extract(ctx, propagation.HeaderCarrier(h))
	if _, ok := SessionID(ctx); ok {
		return ctx
	}
	m, err := baggage.NewMember(audit.BaggageSessionKey, newSessionID())
	if err != nil {
		return ctx
	}
	b, err := baggage.FromContext(ctx).SetMember(m)
	if err != nil {
		return ctx
	}
	return baggage.ContextWithBaggage(ctx, b)
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	return hex.EncodeToString(b[:])
}
