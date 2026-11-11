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
// the inbound W3C baggage member when there is one, a minted one otherwise.
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

// withSession returns ctx with a session.id baggage member: the one already in
// ctx, else the one in the request's baggage header, else a minted one.
func withSession(ctx context.Context, h http.Header) context.Context {
	if baggage.FromContext(ctx).Member(audit.BaggageSessionKey).Key() != "" {
		return ctx
	}
	ctx = propagation.Baggage{}.Extract(ctx, propagation.HeaderCarrier(h))
	b := baggage.FromContext(ctx)
	if b.Member(audit.BaggageSessionKey).Key() != "" {
		return ctx
	}
	m, err := baggage.NewMember(audit.BaggageSessionKey, newSessionID())
	if err != nil {
		return ctx
	}
	b, err = b.SetMember(m)
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
