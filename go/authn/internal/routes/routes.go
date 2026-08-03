package routes

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

type Route interface {
	Name() string
	Pattern() string
	Method() string
	Handler() http.HandlerFunc
}

func Serve(all []Route, log zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(wri http.ResponseWriter, req *http.Request) {
		var allow []string
		for _, route := range all {
			if req.URL.Path != route.Pattern() {
				continue
			}

			if req.Method != route.Method() {
				allow = append(allow, route.Method())
				continue
			}

			lc := log.With()
			// Correlate logs with the active trace when one is present. When
			// tracing is OFF, no span is recorded in the context, SpanContext
			// is invalid, and no trace_id/span_id fields are added — the log
			// output is byte-identical to the un-instrumented service.
			if sc := trace.SpanContextFromContext(req.Context()); sc.IsValid() {
				lc = lc.
					Str("trace_id", sc.TraceID().String()).
					Str("span_id", sc.SpanID().String())
			}
			l := lc.Logger()
			req = req.WithContext(l.WithContext(req.Context()))
			route.Handler()(wri, req)
			return
		}

		if len(allow) > 0 {
			wri.Header().Set("Allow", strings.Join(allow, ", "))
			http.Error(wri, "405 method not allowed", http.StatusMethodNotAllowed)
			return
		}

		http.NotFound(wri, req)
	})
}
