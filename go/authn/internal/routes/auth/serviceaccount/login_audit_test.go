package serviceaccount

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"k8s.io/client-go/rest"
)

// A caller the TokenReview verified is a record however authn refused or
// failed it at the mapping lookup (authn#132): denied with its reason, or a
// failure carrying the apiserver's answer only when one came. A caller refused
// before verification, the wrong audience included, is no record.
func TestRefusalsAfterVerificationAreRecorded(t *testing.T) {
	const cdc = "system:serviceaccount:krateo-system:cdc"
	review := func(body string) apiReplies {
		r := defaultReplies()
		r.tokenReview = body
		return r
	}
	lookup := func(code int, body string) apiReplies {
		r := defaultReplies()
		r.mappingsCode, r.mappings = code, body
		return r
	}
	for _, tc := range []struct {
		name    string
		replies apiReplies
		user    string // "" when no record is owed
		outcome string
		reason  string
		status  string // the record's http.response.status_code, "" for none
	}{
		{name: "not authenticated", replies: review(`{"kind":"TokenReview","status":{"authenticated":false}}`)},
		{name: "wrong audience: not verified for authn", replies: review(`{"kind":"TokenReview","status":{"authenticated":true,
			"audiences":["kube-apiserver"],"user":{"username":"system:serviceaccount:krateo-system:cdc"}}}`)},
		{name: "the token review fails", replies: func() apiReplies { r := defaultReplies(); r.tokenReviewCode = 500; return r }()},

		{name: "not a service account", user: "alice", outcome: audit.OutcomeDenied, reason: "not_a_service_account",
			replies: review(`{"kind":"TokenReview","status":{"authenticated":true,"audiences":["authn"],"user":{"username":"alice"}}}`)},
		{name: "no mapping", user: cdc, outcome: audit.OutcomeDenied, reason: "no_mapping",
			replies: lookup(http.StatusOK, mappingList())},
		{name: "ambiguous mapping", user: cdc, outcome: audit.OutcomeDenied, reason: "ambiguous_mapping",
			replies: lookup(http.StatusOK, mappingList(mappingCdc, strings.Replace(mappingCdc, "cdc-identity", "cdc-other", 1)))},
		{name: "the lookup is refused by the apiserver", user: cdc, outcome: audit.OutcomeFailure, status: "403",
			replies: lookup(http.StatusForbidden, "")},
		{name: "the lookup fails at the apiserver", user: cdc, outcome: audit.OutcomeFailure, status: "500",
			replies: lookup(http.StatusInternalServerError, "")},
		{name: "nothing answers the lookup", user: cdc, outcome: audit.OutcomeFailure,
			replies: lookup(noAnswer, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			srv := fakeAPIServer(t, tc.replies)
			defer srv.Close()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			rec, records := auditlogtest.New(t)
			gen := &fakeGenerator{}
			route := Login(&rest.Config{Host: srv.URL, Timeout: 5 * time.Second}, LoginOptions{
				KubeconfigGenerator: gen, Audit: rec, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k",
			})
			req := httptest.NewRequest(http.MethodPost, Path, nil)
			req.Header.Set("Authorization", "Bearer projected-sa-token")
			w := httptest.NewRecorder()
			auditlog.Middleware(route.Handler()).ServeHTTP(w, req)
			require.NotEqual(t, http.StatusOK, w.Code, w.Body.String())
			assert.Empty(t, gen.calls, "nothing is minted")

			if tc.user == "" {
				assert.Empty(t, records.Records(), "a caller refused before verification is no record")
				return
			}
			// Incomplete by design, each gap marked: with no mapping, neither the
			// actor's class (a mapping declares it) nor a verb is known.
			r := records.Only(t)
			audittest.AssertConformant(t, audit.WriterRequest, r,
				audittest.AllowIncomplete("krateo.audit.actor_class", audit.KeyVerb, "http.request.method", "krateo.audit.preview"))
			assert.Equal(t, auditlog.LoginAction("serviceaccount"), auditlogtest.String(r, "krateo.action"))
			assert.Equal(t, tc.user, auditlogtest.String(r, "user.name"), "the identity the TokenReview verified")
			assert.Equal(t, tc.outcome, auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, tc.reason, auditlogtest.String(r, "krateo.audit.denial_reason"))
			assert.Equal(t, tc.status, attrString(r, "http.response.status_code"),
				"the apiserver's answer to the lookup, never authn's own 500")
			assert.Equal(t, "serviceaccounts", auditlogtest.String(r, "krateo.audit.object_ref.resource"))
			assert.Equal(t, "serviceaccount.authn.krateo.io", auditlogtest.String(r, "krateo.audit.object_ref.api_group"))
			assert.Equal(t, "krateo-system", auditlogtest.String(r, "k8s.namespace.name"))
			assert.Empty(t, auditlogtest.String(r, "krateo.audit.object_ref.name"), "no mapping can be named")
		})
	}
}

// attrString is a record attribute as text, whatever its type, or "" when
// absent.
func attrString(r sdklog.Record, key string) string {
	for _, kv := range audittest.Attributes(r) {
		if string(kv.Key) == key {
			return kv.Value.String()
		}
	}
	return ""
}

// A mapped service account authn verified, whose issuance the name guard
// refuses or whose Secret write fails, is one conformant record of the Secret:
// denied with the guard's reason and no status code, or a failure carrying the
// create sent and the apiserver's answer (AUDIT-4).
func TestIssuanceOutcomesAfterTheMappingAreRecorded(t *testing.T) {
	const name = "cdc-identity"
	for _, tc := range []struct {
		label   string
		err     error
		written storage.Written
		code    int
		check   func(t *testing.T, records *audittest.Recorder)
	}{
		{label: "the name guard refuses: denied",
			err: kubeconfig.Refused(kubeconfig.RefusalClaimed,
				status.Refused(status.CauseUsernameUnavailable, errors.New("the username isn't available to this identity"))),
			written: storage.Written{Namespace: "krateo-system", Name: storage.ClientConfigSecretName(name), Verb: "create"},
			code:    http.StatusForbidden,
			check: func(t *testing.T, records *audittest.Recorder) {
				r := auditlogtest.Only(t, records)
				assert.Equal(t, "authn.login.serviceaccount", auditlogtest.String(r, "krateo.action"))
				assert.Equal(t, audit.OutcomeDenied, auditlogtest.String(r, "krateo.audit.outcome"))
				assert.Equal(t, audit.DenialReasonNameClaimed, auditlogtest.String(r, "krateo.audit.denial_reason"))
				assert.Equal(t, storage.ClientConfigSecretName(name), auditlogtest.String(r, "krateo.audit.object_ref.name"))
				_, ok := auditlogtest.Int(r, "http.response.status_code")
				assert.False(t, ok, "authn refused before asking the apiserver")
			}},
		{label: "the Secret write fails: failure",
			err:     errors.New("creating the session Secret: InternalError (500)"),
			written: auditlogtest.WriteFailed(name, http.StatusInternalServerError),
			code:    http.StatusInternalServerError,
			check: func(t *testing.T, records *audittest.Recorder) {
				auditlogtest.OnlyWriteFailed(t, records, "authn.login.serviceaccount", name, http.StatusInternalServerError)
			}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			srv := fakeAPIServer(t)
			defer srv.Close()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			rec, records := auditlogtest.New(t)
			gen := &fakeGenerator{err: tc.err, written: tc.written}
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{
				KubeconfigGenerator: gen, Audit: rec, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k",
			})
			req := httptest.NewRequest(http.MethodPost, Path, nil)
			req.Header.Set("Authorization", "Bearer projected-sa-token")
			w := httptest.NewRecorder()
			auditlog.Middleware(route.Handler()).ServeHTTP(w, req)
			require.Equal(t, tc.code, w.Code, w.Body.String())
			assert.Equal(t, []string{name}, gen.calls, "issuance was attempted for the mapped caller")
			tc.check(t, records)
		})
	}
}
