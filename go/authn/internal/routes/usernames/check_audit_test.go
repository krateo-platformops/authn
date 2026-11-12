package usernames

import (
	"encoding/json"
	"errors"
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

// A record with no name to read has no verb: those gaps are marked, not
// guessed. One with no mapping has no actor class either, nor a preview of a
// named object.
var (
	nameless = []string{audit.KeyVerb, "http.request.method"}
	unmapped = []string{"krateo.audit.actor_class", audit.KeyVerb, "http.request.method", "krateo.audit.preview"}
)

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
			var allow []string
			if tc.user == "" {
				allow = nameless
			}
			r := only(t, rec, allow...)

			assert.Equal(t, auditlog.ActionUsernameCheck, auditlogtest.String(r, "krateo.action"))
			assert.Equal(t, audit.OutcomeSuccess, auditlogtest.String(r, audit.KeyOutcome))
			assert.Equal(t, tc.result, auditlogtest.String(r, audit.KeyCheckResult))
			assert.Equal(t, "identity-lifecycle-controller", auditlogtest.String(r, "user.name"), "the actor is the caller's mapping")
			assert.Equal(t, "service", auditlogtest.String(r, "krateo.audit.actor_class"))
			assert.Equal(t, "secrets", auditlogtest.String(r, "krateo.audit.object_ref.resource"))
			assert.Equal(t, "krateo-system", auditlogtest.String(r, "k8s.namespace.name"))
			if tc.user == "" {
				assert.False(t, has(r, "krateo.audit.object_ref.name"), "no name, no Secret named")
				assert.False(t, has(r, "krateo.audit.verb"), "a nameless target's verb is marked missing, not guessed")
			} else {
				assert.Equal(t, storage.ClientConfigSecretName(tc.user), auditlogtest.String(r, "krateo.audit.object_ref.name"),
					"the Secret a sign-in under that name writes, so the check joins its refusals and logins")
				assert.Equal(t, "get", auditlogtest.String(r, "krateo.audit.verb"))
				assert.Equal(t, http.MethodGet, auditlogtest.String(r, "http.request.method"),
					"the method follows the verb, not the inbound POST")
			}
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
			switch {
			case tc.user != "identity-lifecycle-controller":
				allow = unmapped
			case tc.object == "":
				allow = nameless
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
