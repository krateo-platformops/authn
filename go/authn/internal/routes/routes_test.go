package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/authn/internal/auditlog"
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

// A caller sets session.id. One that isn't audit's session_id format
// (audit#32: an email, a forged log line, an escape sequence, more than 128
// characters) never reaches a log line: Middleware
// replaces it with a minted one, which the log line and the audit record then
// share.
func TestAMalformedSessionIDIsReplaced(t *testing.T) {
	for name, inbound := range map[string]string{
		"an email":           "zz-sentinel%40example.test",
		"a forged log line":  "x%0A%7B%22level%22%3A%22info%22%7D",
		"an escape sequence": "x%1B%5B31m",
		"a bare newline":     "a%0Ab",
		"a bare ESC":         "a%1Bb",
		"too long":           strings.Repeat("A", 129),
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			var recorded string
			inner := Serve([]Route{logRoute{}, sessionRoute{&recorded}}, zerolog.New(&buf))
			h := auditlog.Middleware(inner)
			req := httptest.NewRequest(http.MethodGet, "/log", nil)
			req.Header.Set("baggage", "session.id="+inbound)
			h.ServeHTTP(httptest.NewRecorder(), req)
			req = httptest.NewRequest(http.MethodGet, "/session", nil)
			req.Header.Set("baggage", "session.id="+inbound)
			h.ServeHTTP(httptest.NewRecorder(), req)

			var line map[string]any
			require.NoError(t, json.Unmarshal(bytes.Split(buf.Bytes(), []byte("\n"))[0], &line), buf.String())
			id, _ := line["session.id"].(string)
			assert.True(t, auditlog.ValidSessionID(id), "a minted id: %q", id)
			sent, err := url.PathUnescape(inbound)
			require.NoError(t, err)
			assert.NotEqual(t, sent, id, "the inbound value is replaced")
			assert.NotEqual(t, sent, recorded, "in the audit record's join key too")
			assert.NotContains(t, buf.String(), "zz-sentinel")
			assert.True(t, auditlog.ValidSessionID(recorded), "the audit record's join key is well-formed too: %q", recorded)
		})
	}
}

// A well-formed inbound session.id is kept, by Middleware and the log line:
// dots are part of audit's session_id format, and so is a UUID.
func TestAWellFormedSessionIDIsKept(t *testing.T) {
	for _, id := range []string{"portal.abc123", "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b", "portal_7f3a-01", strings.Repeat("A", 128)} {
		var buf bytes.Buffer
		h := auditlog.Middleware(Serve([]Route{logRoute{}}, zerolog.New(&buf)))
		req := httptest.NewRequest(http.MethodGet, "/log", nil)
		req.Header.Set("baggage", "session.id="+id+",other=x")
		h.ServeHTTP(httptest.NewRecorder(), req)
		var line map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &line), buf.String())
		assert.Equal(t, id, line["session.id"])
	}
}

// sessionRoute records the session.id an audit record would carry: the
// baggage member audit reads.
type sessionRoute struct{ got *string }

func (sessionRoute) Name() string    { return "session" }
func (sessionRoute) Pattern() string { return "/session" }
func (sessionRoute) Method() string  { return http.MethodGet }
func (r sessionRoute) Handler() http.HandlerFunc {
	return func(_ http.ResponseWriter, req *http.Request) {
		*r.got = baggage.FromContext(req.Context()).Member(audit.BaggageSessionKey).Value()
	}
}

// Without Middleware, a malformed session.id on the context is left out of
// the line, never repeated.
func TestServeOmitsAMalformedSessionID(t *testing.T) {
	var buf bytes.Buffer
	h := Serve([]Route{logRoute{}}, zerolog.New(&buf))
	m, err := baggage.NewMemberRaw(audit.BaggageSessionKey, "zz-sentinel@example.test")
	require.NoError(t, err)
	b, err := baggage.New(m)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/log", nil)
	h.ServeHTTP(httptest.NewRecorder(), req.WithContext(baggage.ContextWithBaggage(req.Context(), b)))
	assert.NotContains(t, buf.String(), "session.id")
	assert.NotContains(t, buf.String(), "zz-sentinel")
}
