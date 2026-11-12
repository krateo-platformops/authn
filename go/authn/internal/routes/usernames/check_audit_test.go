package usernames

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// checkAudited is check with an audit Recorder, returning what it recorded.
func checkAudited(t *testing.T, rc *rest.Config, l *lookup, bearer, body string) (*httptest.ResponseRecorder, *audittest.Recorder) {
	t.Helper()
	ar, rec := auditlogtest.New(t)
	h := Route(rc, Options{Audience: "authn", Lookup: l, Audit: ar}).Handler()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp := httptest.NewRecorder()
	// As main serves it: the middleware stamps the received time and session.id.
	auditlog.Middleware(h).ServeHTTP(resp, req)
	return resp, rec
}

// only returns the single record, after checking that it conforms for the
// request writer with only the allowed gaps marked, that Check catches each
// required key's removal, and that every closed-set value it carries
// (check_result and denial_reason among them) is enforced.
func only(t *testing.T, rec *audittest.Recorder, allowIncomplete ...string) sdklog.Record {
	t.Helper()
	r := rec.Only(t)
	opt := audittest.AllowIncomplete(allowIncomplete...)
	audittest.AssertConformant(t, audit.WriterRequest, r, opt)
	audittest.AssertRequiredKeysDetected(t, audit.WriterRequest, r, opt)
	audittest.AssertEnumsDetected(t, audit.WriterRequest, r, opt)
	return r
}

// A record with no mapping has no actor class, verb or preview: those gaps are
// marked, not guessed (as on /serviceaccount/login). Every other record is
// complete, a nameless one included: the check is a read whatever the name.
var unmapped = []string{"krateo.audit.actor_class", audit.KeyVerb, "http.request.method", "krateo.audit.preview"}

// has reports whether the record carries key.
func has(r sdklog.Record, key string) bool {
	for _, kv := range audittest.Attributes(r) {
		if string(kv.Key) == key {
			return true
		}
	}
	return false
}

func statusCode(r sdklog.Record) (int64, bool) {
	for _, kv := range audittest.Attributes(r) {
		if string(kv.Key) == "http.response.status_code" {
			return kv.Value.AsInt64(), true
		}
	}
	return 0, false
}

// Every completed check is one conformant success record: the caller's
// mapping as actor, a read (get, GET) of the checked name's clientconfig
// Secret, and the answer as check_result, never as a denial.
func TestCheckRecords(t *testing.T) {
	rc := apiserver(t, review(caller), mappings(optedIn))
	claimed := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{storage.ClaimAnnotation: `["oidc","kc","9"]`}}}
	for _, tc := range []struct {
		name   string
		user   string
		l      lookup
		result string
	}{
		{"available", "alice", lookup{}, audit.CheckResultAvailable},
		{"invalid", "Alice@Example", lookup{}, audit.CheckResultInvalid},
		{"invalid, and too long", strings.Repeat("a", 300), lookup{}, audit.CheckResultInvalid},
		{"reserved, and rewritten", "system:admin", lookup{}, audit.CheckResultReserved},
		{"empty", "", lookup{}, audit.CheckResultInvalid},
		{"reserved", "admin", lookup{}, audit.CheckResultReserved},
		{"name_claimed", "alice", lookup{secret: claimed}, audit.CheckResultNameClaimed},
		{"name_held_legacy", "alice", lookup{secret: &corev1.Secret{}}, audit.CheckResultNameHeldLegacy},
		{"name_provisioned", "alice", lookup{provisioned: true}, audit.CheckResultNameProvisioned},
		{"name_bound", "alice", lookup{bound: true}, audit.CheckResultNameBound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"username": tc.user})
			resp, rec := checkAudited(t, rc, &tc.l, "t", string(body))
			require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
			r := only(t, rec)

			assert.Equal(t, auditlog.ActionUsernameCheck, auditlogtest.String(r, "krateo.action"))
			assert.Equal(t, audit.OutcomeSuccess, auditlogtest.String(r, audit.KeyOutcome))
			assert.Equal(t, tc.result, auditlogtest.String(r, audit.KeyCheckResult))
			assert.Equal(t, "identity-lifecycle-controller", auditlogtest.String(r, "user.name"), "the actor is the caller's mapping")
			assert.Equal(t, "service", auditlogtest.String(r, "krateo.audit.actor_class"))
			assert.Equal(t, "secrets", auditlogtest.String(r, "krateo.audit.object_ref.resource"))
			assert.Equal(t, "krateo-system", auditlogtest.String(r, "k8s.namespace.name"))
			switch tc.user {
			case "", "Alice@Example", strings.Repeat("a", 300), "system:admin":
				assert.False(t, has(r, "krateo.audit.object_ref.name"),
					"the derived Secret isn't this name's own: naming it could land on another user's")
			default:
				assert.Equal(t, storage.ClientConfigSecretName(tc.user), auditlogtest.String(r, "krateo.audit.object_ref.name"),
					"the Secret a sign-in under that name writes, so the check joins its refusals and logins")
			}
			assert.Equal(t, "get", auditlogtest.String(r, "krateo.audit.verb"), "a read, whatever the name")
			assert.Equal(t, http.MethodGet, auditlogtest.String(r, "http.request.method"),
				"the method follows the verb, not the inbound POST")
			assert.False(t, has(r, audit.KeyDenialReason), "the caller wasn't refused")
			_, ok := statusCode(r)
			assert.False(t, ok, "a completed check carries no authority answer")
			assert.Equal(t, Path, auditlogtest.String(r, "krateo.request.uri"))
		})
	}
}

// Each refusal or failure after the TokenReview verified the caller is one
// conformant record; a caller refused before verification gets none.
func TestCheckRefusalRecords(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "alice-clientconfig", errors.New("rbac"))
	for _, tc := range []struct {
		name     string
		review   string
		mappings string
		bearer   string
		body     string
		l        lookup

		record  bool
		outcome string
		reason  string
		user    string // the record's user.name
		object  string // the record's object_ref.name, "" for none
		code    int64  // the record's status code, 0 for none
	}{
		{name: "no bearer", review: review(caller), mappings: mappings(optedIn), body: `{"username":"alice"}`},
		{name: "token not authenticated", review: `{"kind":"TokenReview","status":{"authenticated":false}}`, mappings: mappings(optedIn),
			bearer: "t", body: `{"username":"alice"}`},
		{name: "not a service account", review: review("alice"), mappings: mappings(optedIn), bearer: "t", body: `{"username":"bob"}`,
			record: true, outcome: audit.OutcomeDenied, reason: audit.DenialReasonNotAServiceAccount, user: "alice"},
		{name: "no mapping", review: review(caller), mappings: mappings(""), bearer: "t", body: `{"username":"alice"}`,
			record: true, outcome: audit.OutcomeDenied, reason: audit.DenialReasonNoMapping, user: caller},
		{name: "a mapping that didn't opt in", review: review(caller), mappings: mappings(`,"delegation":{"allowed":true}`), bearer: "t",
			body: `{"username":"alice"}`, record: true, outcome: audit.OutcomeDenied, reason: audit.DenialReasonUsernameCheckNotAllowed,
			user: "identity-lifecycle-controller", object: "alice-clientconfig"},
		{name: "not opted in, and no username", review: review(caller), mappings: mappings(`,"usernameCheck":{"allowed":false}`), bearer: "t",
			body: `{}`, record: true, outcome: audit.OutcomeDenied, reason: audit.DenialReasonUsernameCheckNotAllowed,
			user: "identity-lifecycle-controller"},
		{name: "no username", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `{}`,
			record: true, outcome: audit.OutcomeDenied, user: "identity-lifecycle-controller"},
		{name: "not JSON", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `username=alice`,
			record: true, outcome: audit.OutcomeDenied, user: "identity-lifecycle-controller"},
		{name: "a lookup fails, nothing answered", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `{"username":"alice"}`,
			l: lookup{err: errors.New("connection refused")}, record: true, outcome: audit.OutcomeFailure,
			user: "identity-lifecycle-controller", object: "alice-clientconfig"},
		{name: "a lookup fails, the apiserver answered", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `{"username":"alice"}`,
			l: lookup{err: forbidden}, record: true, outcome: audit.OutcomeFailure,
			user: "identity-lifecycle-controller", object: "alice-clientconfig", code: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, rec := checkAudited(t, apiserver(t, tc.review, tc.mappings), &tc.l, tc.bearer, tc.body)
			require.NotEqual(t, http.StatusOK, resp.Code, resp.Body.String())
			if !tc.record {
				assert.Empty(t, rec.Records(), "a caller refused before verification has no verified identity to record")
				return
			}
			var allow []string
			if tc.user != "identity-lifecycle-controller" {
				allow = unmapped
			}
			r := only(t, rec, allow...)
			assert.Equal(t, auditlog.ActionUsernameCheck, auditlogtest.String(r, "krateo.action"))
			assert.Equal(t, tc.outcome, auditlogtest.String(r, audit.KeyOutcome))
			assert.Equal(t, tc.reason, auditlogtest.String(r, audit.KeyDenialReason))
			assert.Equal(t, tc.reason != "", has(r, audit.KeyDenialReason))
			assert.Equal(t, tc.user, auditlogtest.String(r, "user.name"))
			assert.Equal(t, tc.object, auditlogtest.String(r, "krateo.audit.object_ref.name"))
			assert.False(t, has(r, audit.KeyCheckResult), "the check never completed: no result")
			code, ok := statusCode(r)
			assert.Equal(t, tc.code != 0, ok, "a status code only when the apiserver answered")
			assert.Equal(t, tc.code, code)
		})
	}
}

// Every answer CheckUsername can give has a check_result audit declares, so no
// success record ever lacks one or carries one Check refuses.
func TestEveryAnswerHasACheckResult(t *testing.T) {
	answers := append([]kubeconfig.Unavailable{""}, kubeconfig.Unavailables...)
	seen := map[string]bool{}
	for _, why := range answers {
		got := checkResult(why)
		assert.NotEmpty(t, got, "answer %q", why)
		assert.False(t, seen[got], "answers %q share a check_result", why)
		seen[got] = true
	}
	assert.Len(t, checkResults, len(answers), "checkResults maps an answer CheckUsername never gives")
}

// Two names the Secret derivation rewrites to the same Secret, which a
// well-formed user may own, name neither it nor any other: a query for that
// user's Secret never shows checks for names that were never theirs. The
// well-formed name itself is named.
func TestARewrittenNameNeverNamesAnotherUsersSecret(t *testing.T) {
	rc := apiserver(t, review(caller), mappings(optedIn))
	owner := storage.ClientConfigSecretName("aliceexample")
	for _, user := range []string{"Alice@Example", "alice:example"} {
		require.Equal(t, owner, storage.ClientConfigSecretName(user), "the premise: %q aliases aliceexample's Secret", user)
		body, _ := json.Marshal(map[string]string{"username": user})
		resp, rec := checkAudited(t, rc, &lookup{}, "t", string(body))
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		r := only(t, rec)
		assert.False(t, has(r, "krateo.audit.object_ref.name"), "%q names a Secret", user)
	}
	body, _ := json.Marshal(map[string]string{"username": "aliceexample"})
	_, rec := checkAudited(t, rc, &lookup{}, "t", string(body))
	assert.Equal(t, owner, auditlogtest.String(only(t, rec), "krateo.audit.object_ref.name"))
}

// apiserverAnswering is apiserver whose mapping list answers code with body.
func apiserverAnswering(t *testing.T, tokenReview string, code int, body string) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			_, _ = w.Write([]byte(tokenReview))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// The mapping lookup's refusals and failures on this route are recorded under
// authn.username.check, with this action's own bodies.
func TestCheckMappingLookupRecords(t *testing.T) {
	item := `{"metadata":{"name":"%s","namespace":"krateo-system"},"spec":{"serviceAccountRef":{"namespace":"krateo-system","name":"identity-lifecycle-controller"}}}`
	two := `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[` +
		strings.ReplaceAll(item, "%s", "a") + `,` + strings.ReplaceAll(item, "%s", "b") + `]}`
	status500 := `{"kind":"Status","apiVersion":"v1","status":"Failure","code":500,"reason":"InternalError"}`
	for _, tc := range []struct {
		name    string
		code    int
		body    string
		outcome string
		reason  string
		message string
		status  int64
	}{
		{"no mapping", 200, mappings(""), audit.OutcomeDenied, audit.DenialReasonNoMapping, "username check refused", 0},
		{"ambiguous mapping", 200, two, audit.OutcomeDenied, audit.DenialReasonAmbiguousMapping, "username check refused", 0},
		{"the lookup fails at the apiserver", 500, status500, audit.OutcomeFailure, "", "username check failed", 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, rec := checkAudited(t, apiserverAnswering(t, review(caller), tc.code, tc.body), &lookup{}, "t", `{"username":"alice"}`)
			require.NotEqual(t, http.StatusOK, resp.Code)
			r := only(t, rec, unmapped...)
			assert.Equal(t, auditlog.ActionUsernameCheck, auditlogtest.String(r, "krateo.action"))
			assert.Equal(t, tc.outcome, auditlogtest.String(r, audit.KeyOutcome))
			assert.Equal(t, tc.reason, auditlogtest.String(r, audit.KeyDenialReason))
			assert.Equal(t, tc.message, r.Body().AsString(), "this action's own body, not a login's")
			code, ok := statusCode(r)
			assert.Equal(t, tc.status != 0, ok)
			assert.Equal(t, tc.status, code)
		})
	}
}

// The actor's class is the one its mapping declares.
func TestCheckRecordsTheMappingsClass(t *testing.T) {
	for principal, want := range map[string]string{"": "service", "agent": "agent", "controller": "controller"} {
		spec := optedIn
		if principal != "" {
			spec += `,"principal":"` + principal + `"`
		}
		_, rec := checkAudited(t, apiserver(t, review(caller), mappings(spec)), &lookup{}, "t", `{"username":"alice"}`)
		assert.Equal(t, want, auditlogtest.String(only(t, rec), "krateo.audit.actor_class"), "principal %q", principal)
	}
}

// A lookup error the guard wrapped still yields the apiserver's code, as
// Provisioned and BoundAsUser wrap it.
func TestCheckRecordsAWrappedAnswer(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "users"}, "alice", errors.New("rbac"))
	_, rec := checkAudited(t, apiserver(t, review(caller), mappings(optedIn)),
		&lookup{err: fmt.Errorf("reading User %q: %w", "alice", forbidden)}, "t", `{"username":"alice"}`)
	code, ok := statusCode(only(t, rec))
	assert.True(t, ok)
	assert.Equal(t, int64(http.StatusForbidden), code)
}

// countingReader is an endless body that counts what was read from it.
type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	c.n += len(p)
	return len(p), nil
}

// A body is read up to its bound and no further, from any mapped caller, opted
// in or not (the refusal reads it to name the asked-about name).
func TestCheckReadsABoundedBody(t *testing.T) {
	for name, spec := range map[string]string{"opted in": optedIn, "not opted in": ""} {
		t.Run(name, func(t *testing.T) {
			ar, _ := auditlogtest.New(t)
			h := Route(apiserver(t, review(caller), mappings(spec+`,"x":1`)), Options{Audience: "authn", Lookup: &lookup{}, Audit: ar}).Handler()
			body := &countingReader{}
			req := httptest.NewRequest(http.MethodPost, Path, body)
			req.Header.Set("Authorization", "Bearer t")
			resp := httptest.NewRecorder()
			auditlog.Middleware(h).ServeHTTP(resp, req)
			assert.NotEqual(t, http.StatusOK, resp.Code)
			assert.LessOrEqual(t, body.n, maxBody+1, "the body was read past its bound")
		})
	}
}
