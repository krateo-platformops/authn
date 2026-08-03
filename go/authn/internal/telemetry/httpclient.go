package telemetry

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// HTTPClient returns an *http.Client to use for outbound calls.
//
// When tracing is opted in (OTEL_TRACING_ENABLED), the returned client has an
// otelhttp.NewTransport wrapping http.DefaultTransport so the active span's
// traceparent/baggage are injected into the outbound request headers (W3C trace
// context propagation to snowplow / the OIDC provider).
//
// When tracing is OFF this returns http.DefaultClient unchanged — the off-path
// is byte-identical to the previous direct use of http.DefaultClient, and
// http.DefaultTransport is never mutated.
func HTTPClient() *http.Client {
	if !TracingEnabled() {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}
