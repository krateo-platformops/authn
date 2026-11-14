package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/middlewares/cors"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/routes/health"
	"github.com/krateo-platformops/authn/internal/telemetry"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// newListeners builds authn's two servers, as main runs them: the routes
// (listenerHandlers), their instrumentation and the public one's CORS
// (wrapListeners), each on its own port (newServers). main calls only this, so
// TestNewListeners pins the whole composition.
func newListeners(o routeOptions, log zerolog.Logger, corsOn bool, publicPort, internalPort int, internalTLS *tls.Config) (*http.Server, *http.Server, error) {
	public, internal, err := listenerHandlers(o, log)
	if err != nil {
		return nil, nil, fmt.Errorf("building routes: %w", err)
	}
	public, internal = wrapListeners(public, internal, corsOn)
	return newServers(public, internal, publicPort, internalPort, internalTLS)
}

// listenerHandlers builds the two listeners' handlers. The public one serves
// buildRoutes; the internal one serves only what in-cluster services call
// (buildInternalRoutes), and the public one never serves its paths: whether a
// username is held is decided in-cluster, never on a public surface.
// TestListenersServeTheirOwnSurface pins both.
func listenerHandlers(o routeOptions, log zerolog.Logger) (public, internal http.Handler, err error) {
	all, err := buildRoutes(o)
	if err != nil {
		return nil, nil, err
	}
	return auditlog.Middleware(routes.Serve(all, log)),
		auditlog.Middleware(routes.Serve(buildInternalRoutes(o), log)), nil
}

// newServers builds the public server on publicPort and the internal one on
// internalPort, each with its own handler. The two must not share a port: the
// internal listener has its own Service, which no public route references.
// internalTLS, when not nil, is the internal listener's TLS (authn#145);
// listenAndServe then serves it over TLS only.
func newServers(public, internal http.Handler, publicPort, internalPort int, internalTLS *tls.Config) (*http.Server, *http.Server, error) {
	if publicPort == internalPort {
		return nil, nil, fmt.Errorf("the internal listener must not share the public port %d", publicPort)
	}
	return &http.Server{
			Addr:         fmt.Sprintf(":%d", publicPort),
			Handler:      public,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 50 * time.Second,
			IdleTimeout:  30 * time.Second,
		}, &http.Server{
			Addr:         fmt.Sprintf(":%d", internalPort),
			Handler:      internal,
			TLSConfig:    internalTLS,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 20 * time.Second,
			IdleTimeout:  30 * time.Second,
		}, nil
}

// shutdownServers stops every server at once: each stops accepting and drains
// within ctx, concurrently, so one draining never keeps another accepting. It
// returns every server's error.
func shutdownServers(ctx context.Context, servers ...*http.Server) error {
	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		s.SetKeepAlivesEnabled(false)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Shutdown(ctx); err != nil {
				errs[i] = fmt.Errorf("%s: %w", s.Addr, err)
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// flushTimeout bounds the telemetry and audit flush at shutdown, which runs on
// its own context after the servers have drained.
const flushTimeout = 10 * time.Second

// wrapListeners instruments both handlers (each request is a server span and
// counts in http.server.*, when those pipelines are opted in) and gives the
// public one CORS when corsOn. The internal handler never gets CORS: only
// in-cluster services call it, never a browser. TestWrapListeners pins both.
//
// otelhttp is outermost, so the Server span is active when an audit record
// marks it (auditlog.Middleware is inside, from listenerHandlers).
func wrapListeners(public, internal http.Handler, corsOn bool) (http.Handler, http.Handler) {
	public, internal = instrument(public), instrument(internal)
	if corsOn {
		public = cors.New(cors.Options{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			// traceparent/tracestate/baggage are REQUIRED so the cross-origin
			// browser->authn hop can carry W3C trace context to authn.
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Auth-Code", "X-Code-Verifier", "traceparent", "tracestate", "baggage"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300, // Maximum value not ignored by any of major browsers
		}).Handler(public)
	}
	return public, internal
}

// instrument is OpenTelemetry's HTTP server instrumentation (gated, default
// OFF). When metrics are opted in, it emits http.server.* instruments; when
// tracing is opted in, it wraps with otelhttp so each inbound request becomes a
// server span (named by URL path) and traceparent is extracted. /health is
// filtered out of tracing to avoid probe noise. When both are off, h is
// returned untouched.
func instrument(h http.Handler) http.Handler {
	if telemetry.MetricsEnabled() {
		h = telemetry.MetricsMiddleware(h)
	}
	if telemetry.TracingEnabled() {
		h = otelhttp.NewHandler(h, serviceName,
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return r.URL.Path
			}),
			otelhttp.WithFilter(func(r *http.Request) bool {
				return r.URL.Path != health.Path
			}),
		)
	}
	return h
}
