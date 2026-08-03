package telemetry

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// MetricsMiddleware wraps an http.Handler emitting http.server.* semconv style
// instruments (request count, request duration histogram, error count).
//
// It is GATED: when the metrics pipeline is not opted in (OTEL_METRICS_ENABLED
// false), Setup never registers a real MeterProvider, otel.Meter returns a
// no-op meter, and callers should not wrap the handler at all (see main.go).
// If wrapped anyway with metrics off, the no-op meter makes every record a
// cheap no-op — but the off-path in main.go skips wrapping entirely so the
// handler chain stays byte-identical.
func MetricsMiddleware(next http.Handler) http.Handler {
	meter := otel.Meter("github.com/krateo-platformops/authn")

	requestCount, _ := meter.Int64Counter(
		"http.server.request.count",
		metric.WithDescription("Total number of HTTP requests served."),
		metric.WithUnit("{request}"),
	)
	errorCount, _ := meter.Int64Counter(
		"http.server.error.count",
		metric.WithDescription("Total number of HTTP requests that resulted in a 5xx response."),
		metric.WithUnit("{request}"),
	)
	duration, _ := meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("Duration of inbound HTTP requests."),
		metric.WithUnit("s"),
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		attrs := metric.WithAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("http.route", r.URL.Path),
			attribute.Int("http.response.status_code", sw.status),
		)

		requestCount.Add(r.Context(), 1, attrs)
		duration.Record(r.Context(), time.Since(start).Seconds(), attrs)
		if sw.status >= http.StatusInternalServerError {
			errorCount.Add(r.Context(), 1, attrs)
		}
	})
}

// statusRecorder captures the response status code for metric labelling.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
