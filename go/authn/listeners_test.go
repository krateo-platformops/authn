package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"k8s.io/client-go/rest"
)

func testRouteOptions(t *testing.T) routeOptions {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	healthy := int32(1)
	return routeOptions{
		RestConfig:             &rest.Config{Host: fakeAPIServer(t).URL},
		Generator:              &mintCounter{},
		PrivateKey:             key,
		KeyID:                  "k",
		JwtDuration:            time.Hour,
		ServiceAccountAudience: "authn",
		SelfUsername:           "authn",
		SnowplowURL:            "http://127.0.0.1:1",
		Healthy:                &healthy,
		Version:                "test",
		ServiceName:            "authn",
	}
}

func serve(h http.Handler, method, path string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(`{"username":"alice"}`)))
	return rec.Code
}

// The two listeners serve their own surfaces, as main builds them: the public
// one never answers /usernames/check, and the internal one serves it and
// nothing public.
func TestListenersServeTheirOwnSurface(t *testing.T) {
	public, internal, err := listenerHandlers(testRouteOptions(t), testLogger())
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, serve(public, http.MethodPost, "/usernames/check"),
		"the public listener must not serve /usernames/check")
	assert.Equal(t, http.StatusOK, serve(public, http.MethodGet, "/health"))

	assert.Equal(t, http.StatusUnauthorized, serve(internal, http.MethodPost, "/usernames/check"),
		"the internal listener serves the check (refusing a caller with no bearer)")
	for _, path := range []string{"/health", "/strategies", "/.well-known/jwks.json"} {
		assert.Equal(t, http.StatusNotFound, serve(internal, http.MethodGet, path), "the internal listener serves %s", path)
	}
}

// Each server gets its own handler and port, and the two may not share one.
func TestNewServers(t *testing.T) {
	public, internal, err := listenerHandlers(testRouteOptions(t), testLogger())
	require.NoError(t, err)

	_, _, err = newServers(public, internal, 8082, 8082)
	assert.Error(t, err, "both listeners on one port")

	pub, in, err := newServers(public, internal, 8082, 8090)
	require.NoError(t, err)
	assert.Equal(t, ":8082", pub.Addr)
	assert.Equal(t, ":8090", in.Addr)
	assert.Equal(t, http.StatusNotFound, serve(pub.Handler, http.MethodPost, "/usernames/check"),
		"the public server's handler is the public one")
	assert.Equal(t, http.StatusUnauthorized, serve(in.Handler, http.MethodPost, "/usernames/check"),
		"the internal server's handler is the internal one")
}

// startServer serves h on a free local port and returns the server and its URL.
func startServer(t *testing.T, h http.Handler) (*http.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &http.Server{Addr: ln.Addr().String(), Handler: h}
	go func() { _ = s.Serve(ln) }()
	return s, "http://" + ln.Addr().String()
}

// refusesConnections reports whether nothing accepts at url's address any more.
func refusesConnections(url string) bool {
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(url, "http://"), 200*time.Millisecond)
	if err != nil {
		return true
	}
	_ = c.Close()
	return false
}

// While one server drains a slow request, the other has already stopped
// accepting; and a server forced past the deadline doesn't keep the others
// open. Both errors are reported.
func TestShutdownServersStopsAllAtOnce(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	slow, slowURL := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}))
	other, otherURL := startServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer close(release)

	go func() { _, _ = http.Get(slowURL) }()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shutdownServers(ctx, slow, other) }()

	require.Eventually(t, func() bool { return refusesConnections(otherURL) }, time.Second, 20*time.Millisecond,
		"the second server still accepts while the first drains")

	err := <-done
	require.Error(t, err, "the slow server is forced past the deadline")
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
	assert.Contains(t, err.Error(), slow.Addr)
	assert.NotContains(t, err.Error(), other.Addr, "the server that drained cleanly reports nothing")
	assert.True(t, refusesConnections(otherURL))
}

// preflight is a browser's CORS preflight for path, and the
// Access-Control-Allow-Origin it got back.
func preflight(h http.Handler, path string) string {
	req := httptest.NewRequest(http.MethodOptions, path, nil)
	req.Header.Set("Origin", "https://portal.example.test")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Header().Get("Access-Control-Allow-Origin")
}

// main's wrapping: both listeners are instrumented, and only the public one
// answers a browser's CORS preflight; the internal one never does, whatever
// AUTHN_CORS says.
func TestWrapListeners(t *testing.T) {
	t.Setenv(telemetry.EnvTracingEnabled, "true")
	t.Setenv(telemetry.EnvMetricsEnabled, "false")
	spans := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	public, internal, err := listenerHandlers(testRouteOptions(t), testLogger())
	require.NoError(t, err)

	pub, in := wrapListeners(public, internal, true)
	assert.NotEmpty(t, preflight(pub, "/strategies"), "the public listener answers a CORS preflight when CORS is on")
	assert.Empty(t, preflight(in, "/usernames/check"), "the internal listener must never answer a CORS preflight")

	serve(pub, http.MethodGet, "/strategies")
	serve(in, http.MethodPost, "/usernames/check")
	var names []string
	for _, s := range spans.Ended() {
		names = append(names, s.Name())
	}
	assert.Contains(t, names, "/strategies", "the public listener is instrumented")
	assert.Contains(t, names, "/usernames/check", "the internal listener is instrumented")

	pub, _ = wrapListeners(public, internal, false)
	assert.Empty(t, preflight(pub, "/strategies"), "CORS off: no preflight answer")
}

// The servers main runs: each listener on its own port with its own surface,
// both instrumented, and CORS on the public one only.
func TestNewListeners(t *testing.T) {
	t.Setenv(telemetry.EnvTracingEnabled, "true")
	t.Setenv(telemetry.EnvMetricsEnabled, "false")
	spans := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	_, _, err := newListeners(testRouteOptions(t), testLogger(), true, 8082, 8082)
	assert.Error(t, err, "both listeners on one port")

	pub, in, err := newListeners(testRouteOptions(t), testLogger(), true, 8082, 8090)
	require.NoError(t, err)
	assert.Equal(t, ":8082", pub.Addr)
	assert.Equal(t, ":8090", in.Addr)

	// spanned serves one request and reports whether it ended a server span.
	spanned := func(h http.Handler, method, path string, want int) bool {
		before := len(spans.Ended())
		assert.Equal(t, want, serve(h, method, path), "%s %s", method, path)
		return len(spans.Ended()) > before
	}
	assert.True(t, spanned(pub.Handler, http.MethodGet, "/strategies", http.StatusOK), "the public server is instrumented")
	assert.True(t, spanned(in.Handler, http.MethodPost, "/usernames/check", http.StatusUnauthorized), "the internal server is instrumented")
	assert.Equal(t, http.StatusNotFound, serve(pub.Handler, http.MethodPost, "/usernames/check"))
	assert.Equal(t, http.StatusNotFound, serve(in.Handler, http.MethodGet, "/strategies"))

	assert.NotEmpty(t, preflight(pub.Handler, "/strategies"), "the public server answers a CORS preflight")
	assert.Empty(t, preflight(in.Handler, "/usernames/check"), "the internal server never answers a CORS preflight")

}
