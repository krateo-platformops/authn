package auditlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// provider hands the Recorder audittest's logger, so records go through the
// real SDK.
type provider struct {
	embedded.LoggerProvider
	rec   *audittest.Recorder
	scope string
}

func (p *provider) Logger(name string, _ ...log.LoggerOption) log.Logger {
	p.scope = name
	return p.rec.Logger(name)
}

func newRecorder(t *testing.T) (*Recorder, *audittest.Recorder) {
	rec := audittest.NewRecorder(t)
	r := New(&provider{rec: rec}, func(context.Context, string) (bool, bool) { return false, true })
	return r, rec
}

var testNow = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func alice() userinfo.Info {
	return userinfo.NewDefaultUser("alice", "1", []string{"devs"}, nil)
}

func created() config.Issued {
	return config.Issued{Secret: storage.Written{Namespace: "krateo-system", Name: "alice-clientconfig",
		UID: "uid-1", ResourceVersion: "7", Verb: "create", StatusCode: 201}}
}

func wouldUpdate() config.Issued {
	return config.Issued{Secret: storage.Written{Namespace: "krateo-system", Name: "alice-clientconfig", Verb: "update"}}
}

func refusal() error {
	return config.Refused(config.RefusalBound, status.RefusedPrivately(status.CauseUsernameUnavailable,
		errors.New("the username isn't available"), errors.New("bound")))
}

func get(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = "10.0.0.9:51234"
	req.Header.Set("User-Agent", "test-agent")
	// As Middleware prepares it: received time and a session.id.
	ctx := withSession(context.WithValue(req.Context(), receivedKey{}, testNow), req.Header)
	return req.WithContext(ctx)
}

func attr(t *testing.T, attrs []attribute.KeyValue, key string) (attribute.Value, bool) {
	t.Helper()
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

// Every record shape an issuance can produce conforms for the request writer,
// and Check catches each required key's removal (acceptance 3 and 4).
func TestIssuanceRecordsConform(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  string
		issued  config.Issued
		err     error
		outcome string
	}{
		{"basic login, created", LoginAction(storage.StrategyBasic), created(), nil, audit.OutcomeSuccess},
		{"oidc login, refused by the name guard", LoginAction(storage.StrategyOIDC), wouldUpdate(), refusal(), audit.OutcomeDenied},
		{"oauth login, the write failed", LoginAction(storage.StrategyOAuth),
			config.Issued{Secret: storage.Written{Namespace: "krateo-system", Name: "alice-clientconfig", Verb: "create", StatusCode: 500}},
			errors.New("internal error"), audit.OutcomeFailure},
		{"step-up, created", ActionStepUp,
			config.Issued{Secret: storage.Written{Namespace: "krateo-system", Name: "alice-clientconfig-stepup", UID: "u", ResourceVersion: "1", Verb: "create", StatusCode: 201}},
			nil, audit.OutcomeSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, rec := newRecorder(t)
			r.Issuance(get("/x"), tc.action, alice(), jwtutil.PrincipalHuman, tc.issued, tc.err)
			got := rec.Only(t)
			audittest.AssertConformant(t, audit.WriterRequest, got)
			audittest.AssertRequiredKeysDetected(t, audit.WriterRequest, got)

			attrs := audittest.Attributes(got)
			v, _ := attr(t, attrs, "krateo.audit.outcome")
			assert.Equal(t, tc.outcome, v.AsString())
			v, _ = attr(t, attrs, "krateo.action")
			assert.Equal(t, tc.action, v.AsString())
			v, _ = attr(t, attrs, "krateo.audit.object_ref.name")
			assert.Equal(t, tc.issued.Secret.Name, v.AsString())
			v, _ = attr(t, attrs, "krateo.audit.verb")
			assert.Equal(t, tc.issued.Secret.Verb, v.AsString())
			_, hasStatus := attr(t, attrs, "http.response.status_code")
			assert.Equal(t, tc.outcome != audit.OutcomeDenied, hasStatus,
				"a denial carries no status code: authn refused before asking the apiserver")
		})
	}
}

// The scope is the one audit's schema lists as authn's request population.
func TestRecorderScope(t *testing.T) {
	rec := audittest.NewRecorder(t)
	p := &provider{rec: rec}
	_ = New(p, nil)
	assert.Equal(t, "github.com/krateo-platformops/authn/audit", p.scope)
}

// A record keeps only the query parameters its route reads (name, d): an OAuth
// or OIDC callback's code and state are credentials, and a client can add
// anything else, a token included.
func TestRequestURIDropsCallbackQueries(t *testing.T) {
	for _, tc := range []struct {
		action, want string
	}{
		{LoginAction(storage.StrategyOAuth), "/x?name=kc"},
		{LoginAction(storage.StrategyOIDC), "/x?name=kc"},
		{ActionStepUp, "/x?name=kc"},
		{LoginAction(storage.StrategyLDAP), "/x?name=kc"},
		{LoginAction(storage.StrategyBasic), "/x?d=1"},
		{LoginAction(storage.StrategyServiceAccount), "/x"},
	} {
		r, rec := newRecorder(t)
		r.Issuance(get("/x?name=kc&code=c&state=s&d=1&subject_token=eyJ.x.y"), tc.action, alice(), jwtutil.PrincipalHuman, created(), nil)
		v, _ := attr(t, audittest.Attributes(rec.Only(t)), "krateo.request.uri")
		assert.Equal(t, tc.want, v.AsString(), tc.action)
	}
}

// Acceptance 5: a sentinel identity and a sentinel token reach every value the
// site can see besides the identity it records: the error, the query, the
// credential headers. Neither may appear in the body or in any attribute, and
// the body is a closed set.
func TestNoSentinelLeaks(t *testing.T) {
	const identity, token = "SENTINEL-IDENTITY-6f3a", "eyJSENTINELTOKEN.abc.def"
	for _, tc := range []struct {
		name   string
		action string
		err    error
	}{
		{"failure", LoginAction(storage.StrategyOIDC), fmt.Errorf("IdP answered %s for %s", token, identity)},
		{"denied", LoginAction(storage.StrategyOIDC), config.Refused(config.RefusalClaimed,
			status.RefusedPrivately(status.CauseUsernameUnavailable, fmt.Errorf("%s %s", identity, token), errors.New(token)))},
		{"success", LoginAction(storage.StrategyOAuth), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, rec := newRecorder(t)
			req := get("/oidc/login?name=kc&code=" + token + "&state=" + identity)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Auth-Code", token)
			req.Header.Set("Cookie", "s="+identity)
			r.Issuance(req, tc.action, alice(), jwtutil.PrincipalHuman, created(), tc.err)
			got := rec.Only(t)
			body := got.Body().AsString()
			assert.Contains(t, []string{msgIssued, msgRefused, msgFailed}, body, "the body is a closed set")
			for _, kv := range audittest.Attributes(got) {
				s := kv.Value.Emit()
				assert.NotContains(t, s, identity, "attribute %s", kv.Key)
				assert.NotContains(t, s, token, "attribute %s", kv.Key)
			}
		})
	}
}

// Acceptance 6: a request that wrote a record gets krateo.audit.recorded=true
// on its Server span, and it carries the inbound session.id, or a minted one.
func TestMiddlewareMarksTheServerSpanAndCarriesASession(t *testing.T) {
	for _, tc := range []struct {
		name    string
		baggage string
	}{
		{"inbound session", "session.id=s-123"},
		{"minted session", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spans := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
			r, rec := newRecorder(t)
			h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				r.Issuance(req, LoginAction(storage.StrategyBasic), alice(), jwtutil.PrincipalHuman, created(), nil)
			}))
			req := httptest.NewRequest(http.MethodGet, "/basic/login", nil)
			if tc.baggage != "" {
				req.Header.Set("baggage", tc.baggage)
			}
			ctx, span := tp.Tracer("t").Start(req.Context(), "server", trace.WithSpanKind(trace.SpanKindServer))
			h.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))
			span.End()

			ended := spans.Ended()
			require.Len(t, ended, 1)
			var marked bool
			for _, kv := range ended[0].Attributes() {
				if kv.Key == attribute.Key(audit.SpanKeyRecorded) && kv.Value.AsBool() {
					marked = true
				}
			}
			assert.True(t, marked, "the Server span is marked recorded")

			v, ok := attr(t, audittest.Attributes(rec.Only(t)), audit.BaggageSessionKey)
			require.True(t, ok, "the record carries session.id")
			if tc.baggage != "" {
				assert.Equal(t, "s-123", v.AsString())
			} else {
				assert.Len(t, v.AsString(), 32, "a minted session id")
				assert.False(t, strings.Contains(v.AsString(), "alice"))
			}
		})
	}
}

// Every refusal reaches the record as its schema value, on a denied record that
// conforms; Check would report an unknown value as bad-enum.
func TestEveryRefusalHasADenialReason(t *testing.T) {
	for _, why := range config.Refusals {
		t.Run(string(why), func(t *testing.T) {
			want, ok := denialReasons[why]
			require.True(t, ok, "no schema denial reason for %q", why)
			r, rec := newRecorder(t)
			err := config.Refused(why, status.Refused(status.CauseUsernameUnavailable, errors.New("refused")))
			r.Issuance(get("/oidc/login"), LoginAction(storage.StrategyOIDC), alice(), jwtutil.PrincipalHuman, wouldUpdate(), err)
			got := rec.Only(t)
			audittest.AssertConformant(t, audit.WriterRequest, got)
			v, _ := attr(t, audittest.Attributes(got), audit.KeyDenialReason)
			assert.Equal(t, want, v.AsString())
			assert.Equal(t, string(why), v.AsString(), "authn's refusal names are the schema's")
		})
	}
	assert.Len(t, denialReasons, len(config.Refusals), "no stale entries")

	t.Run("a success or a failure carries none", func(t *testing.T) {
		for _, err := range []error{nil, errors.New("internal")} {
			r, rec := newRecorder(t)
			r.Issuance(get("/oidc/login"), LoginAction(storage.StrategyOIDC), alice(), jwtutil.PrincipalHuman, created(), err)
			_, has := attr(t, audittest.Attributes(rec.Only(t)), audit.KeyDenialReason)
			assert.False(t, has)
		}
	})
}

// A denial wrote nothing: it names no uid or resourceVersion, whatever it was
// handed.
func TestADenialNamesNoStoredObject(t *testing.T) {
	r, rec := newRecorder(t)
	r.Issuance(get("/x"), LoginAction(storage.StrategyOIDC), alice(), jwtutil.PrincipalHuman, created(), refusal())
	attrs := audittest.Attributes(rec.Only(t))
	for _, k := range []string{"krateo.audit.object_ref.uid", "krateo.audit.object_ref.resource_version"} {
		_, has := attr(t, attrs, k)
		assert.False(t, has, k)
	}
}

// The preview flag comes from the target namespace's label, read from the
// apiserver: a sandbox reads true, anything else false, and an unreadable
// namespace leaves it out (marked).
func TestPreviewComesFromTheNamespace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels map[string]string
		err    error
		want   *bool
	}{
		{"sandbox", map[string]string{PreviewLabel: PreviewSandbox}, nil, ptr(true)},
		{"ordinary", map[string]string{"x": "y"}, nil, ptr(false)},
		{"unreadable", nil, errors.New("forbidden"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := audittest.NewRecorder(t)
			src := CachedPreview(func(context.Context, string) (map[string]string, error) { return tc.labels, tc.err }, time.Minute)
			r := New(&provider{rec: rec}, src)
			r.Issuance(get("/x"), LoginAction(storage.StrategyBasic), alice(), jwtutil.PrincipalHuman, created(), nil)
			got := rec.Only(t)
			v, has := attr(t, audittest.Attributes(got), "krateo.audit.preview")
			if tc.want == nil {
				assert.False(t, has)
				audittest.AssertConformant(t, audit.WriterRequest, got, audittest.AllowIncomplete("krateo.audit.preview"))
				return
			}
			require.True(t, has)
			assert.Equal(t, *tc.want, v.AsBool())
			audittest.AssertConformant(t, audit.WriterRequest, got)
		})
	}
}

func ptr[T any](v T) *T { return &v }

// An identity source that verified someone without a username: the record is a
// failure naming no object and no actor, each gap marked, rather than a made-up
// "-clientconfig".
func TestAnIdentityWithoutAUsernameNamesNoSecret(t *testing.T) {
	r, rec := newRecorder(t)
	nobody := userinfo.NewDefaultUser("", "1", nil, nil)
	r.Issuance(get("/x"), LoginAction(storage.StrategyOIDC), nobody, jwtutil.PrincipalHuman, config.Issued{}, errors.New("no username"))
	got := rec.Only(t)
	audittest.AssertConformant(t, audit.WriterRequest, got,
		audittest.AllowIncomplete("user.name", audit.KeyVerb, "http.request.method", "krateo.audit.preview", "target"))
	_, has := attr(t, audittest.Attributes(got), "krateo.audit.object_ref.name")
	assert.False(t, has)
}
