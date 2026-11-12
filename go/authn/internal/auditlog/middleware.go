package auditlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
)

// Middleware prepares each request for its audit records. It stamps when the
// request was received, and it makes sure the context carries a session.id:
// the inbound W3C baggage member when it is a well-formed one (audit.ValidSessionID),
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

// SessionID returns ctx's session.id when it is one authn accepts. After
// Middleware, a request's always is.
func SessionID(ctx context.Context) (string, bool) {
	v := baggage.FromContext(ctx).Member(audit.BaggageSessionKey).Value()
	return v, audit.ValidSessionID(v)
}

// withSession returns ctx with a session.id baggage member authn accepts
// (audit.ValidSessionID): the one already in ctx, else the one in the request's
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
