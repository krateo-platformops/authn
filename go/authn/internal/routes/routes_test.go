package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/baggage"
)

type logRoute struct{}

func (logRoute) Name() string    { return "log" }
func (logRoute) Pattern() string { return "/log" }
func (logRoute) Method() string  { return http.MethodGet }
func (logRoute) Handler() http.HandlerFunc {
	return func(_ http.ResponseWriter, req *http.Request) { zerolog.Ctx(req.Context()).Info().Msg("hello") }
}

// A route's log lines carry the request's session.id, which joins them to its
// audit record: the record names the identity, the log lines never do.
func TestRouteLogsCarryTheSessionID(t *testing.T) {
	var buf bytes.Buffer
	h := Serve([]Route{logRoute{}}, zerolog.New(&buf))

	m, err := baggage.NewMember(audit.BaggageSessionKey, "s-1")
	require.NoError(t, err)
	b, err := baggage.New(m)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/log", nil)
	req = req.WithContext(baggage.ContextWithBaggage(req.Context(), b))
	h.ServeHTTP(httptest.NewRecorder(), req)

	var line map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line), buf.String())
	assert.Equal(t, "s-1", line["session.id"])

	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/log", nil))
	line = nil
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line), buf.String())
	assert.NotContains(t, line, "session.id", "none without one")
}
