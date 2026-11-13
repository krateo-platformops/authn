package serviceaccount

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// fakeGenerator stands in for the kubeconfig generator: it records that the
// identity's clientconfig was minted and returns a kubeconfig carrying a
// private key, as the real one does.
type fakeGenerator struct {
	calls      []string
	strategies []storage.Strategy
	owners     []*metav1.OwnerReference
	subjects   []userinfo.Subject
	err        error
	// written is the write Generate reports with err.
	written storage.Written
}

func (g *fakeGenerator) Generate(strategy storage.Strategy, user userinfo.Info, opts ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	g.strategies = append(g.strategies, strategy)
	g.owners = append(g.owners, kubeconfig.NewIssueOptions(opts...).Owner)
	g.calls = append(g.calls, user.GetUserName())
	g.subjects = append(g.subjects, user.GetSubject())
	if g.err != nil {
		return kubeconfig.Issued{Secret: g.written}, g.err
	}
	return kubeconfig.Issued{Kubeconfig: []byte(`{"kind":"Config","users":[{"name":"x","user":{"client-key-data":"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"}}]}`), NotAfter: time.Now().Add(time.Hour), Secret: auditlogtest.Created(user.GetUserName())}, nil
}

func (g *fakeGenerator) GenerateStepUp(storage.Strategy, userinfo.Info, time.Duration, ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	panic("serviceaccount login never issues a step-up credential")
}

// apiReplies configures fakeAPIServer. Status codes other than 200 make the
// corresponding call fail at the HTTP level.
type apiReplies struct {
	tokenReviewCode int
	tokenReview     string
	mappingsCode    int
	mappings        string
}

const (
	reviewOK = `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
		"status":{"authenticated":true,"audiences":["authn"],
		"user":{"username":"system:serviceaccount:krateo-system:cdc"}}}`
	mappingCdc = `{"metadata":{"name":"cdc-identity","namespace":"krateo-system","uid":"0b1f6c1e-2d6a-4b8e-9c3f-5a7e8d9f0a1b"},
		"spec":{"serviceAccountRef":{"namespace":"krateo-system","name":"cdc"},"groups":["krateo:cdc"]}}`
)

func mappingList(items ...string) string {
	return `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[` +
		strings.Join(items, ",") + `]}`
}

// noAnswer, as an apiReplies code, drops the connection without an answer.
const noAnswer = -1

func defaultReplies() apiReplies {
	return apiReplies{tokenReviewCode: 200, tokenReview: reviewOK, mappingsCode: 200, mappings: mappingList(mappingCdc)}
}

// fakeAPIServer answers the two calls the handler makes: the TokenReview and
// the list of ServiceAccount mappings in the operator namespace.
func fakeAPIServer(t *testing.T, rep ...apiReplies) *httptest.Server {
	t.Helper()
	cfg := defaultReplies()
	if len(rep) > 0 {
		cfg = rep[0]
	}
	// A non-200 answers with a Status carrying that code, as the apiserver
	// does; noAnswer drops the connection, so nothing answers at all.
	reply := func(w http.ResponseWriter, code int, body string) {
		if code == noAnswer {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(code)
		if code != http.StatusOK {
			body = fmt.Sprintf(`{"kind":"Status","apiVersion":"v1","status":"Failure","message":"boom","code":%d}`, code)
		}
		_, _ = w.Write([]byte(body))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			reply(w, cfg.tokenReviewCode, cfg.tokenReview)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			reply(w, cfg.mappingsCode, cfg.mappings)
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

// The serviceaccount login must still mint the identity's clientconfig, but its
// response must not carry that kubeconfig: it holds a private key, and no
// service caller reads it (#36).
func TestHandlerOmitsKubeconfigFromResponse(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := fakeAPIServer(t)
	defer srv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	gen := &fakeGenerator{}
	audit, records := auditlogtest.New(t)
	route := Login(&rest.Config{Host: srv.URL}, LoginOptions{
		KubeconfigGenerator: gen,
		Audit:               audit,
		JwtDuration:         time.Hour,
		JwtPrivateKey:       key,
		JwtKeyID:            "test-key",
	})

	req := httptest.NewRequest(http.MethodPost, Path, nil)
	req.Header.Set("Authorization", "Bearer projected-sa-token")
	rec := httptest.NewRecorder()
	auditlog.Middleware(route.Handler()).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	// One conformant record of the Secret written, as the mapping's principal (AUDIT-4).
	r := auditlogtest.Only(t, records)
	assert.Equal(t, "authn.login.serviceaccount", auditlogtest.String(r, "krateo.action"))
	assert.Equal(t, "cdc-identity-clientconfig", auditlogtest.String(r, "krateo.audit.object_ref.name"))
	assert.Equal(t, []string{"cdc-identity"}, gen.calls, "the clientconfig Secret must still be minted")
	assert.Equal(t, []storage.Strategy{storage.StrategyServiceAccount}, gen.strategies, "issued as the serviceaccount strategy")
	require.Len(t, gen.owners, 1)
	assert.Equal(t, &metav1.OwnerReference{
		APIVersion: "serviceaccount.authn.krateo.io/v1alpha1",
		Kind:       "ServiceAccount",
		Name:       "cdc-identity",
		UID:        "0b1f6c1e-2d6a-4b8e-9c3f-5a7e8d9f0a1b",
	}, gen.owners[0], "the Secret is owned by the mapping that authenticated, by its UID, so retiring the mapping retires the credential")
	assert.Equal(t, []userinfo.Subject{{Issuer: "krateo-system", ID: "cdc"}}, gen.subjects,
		"a service identity is its ServiceAccount, which a re-created mapping keeps")

	var out map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.NotContains(t, out, "data", "the kubeconfig must not be in the response")
	assert.NotContains(t, rec.Body.String(), "client-key-data")
	assert.Contains(t, out, "accessToken")
	assert.Contains(t, out, "user")
	assert.True(t, strings.Contains(string(out["groups"]), "krateo:cdc"))
	assert.JSONEq(t, `{"kind":"serviceaccount"}`, string(out["strategy"]))
}

// Every failure carries a machine-readable cause in details.causes, and its
// status class says whose failure it is: 401/403 for a refused caller, 500 for
// authn failing to finish the job. A client classifies on the code alone.
func TestHandlerFailureCauses(t *testing.T) {
	review := func(body string) apiReplies {
		r := defaultReplies()
		r.tokenReview = body
		return r
	}
	mappings := func(body string) apiReplies {
		r := defaultReplies()
		r.mappings = body
		return r
	}
	failing := func(tokenReview bool) apiReplies {
		r := defaultReplies()
		if tokenReview {
			r.tokenReviewCode = http.StatusInternalServerError
		} else {
			r.mappingsCode = http.StatusInternalServerError
		}
		return r
	}

	cases := []struct {
		name        string
		replies     apiReplies
		noBearer    bool
		keyID       string
		generateErr error
		code        int
		reason      string
		cause       string
		message     string
		minted      bool
	}{
		// Refusals of the caller.
		{name: "no bearer", noBearer: true, code: 401, reason: "Unauthorized", cause: "MissingBearer"},
		{name: "token rejected by the apiserver", code: 403, reason: "Forbidden", cause: "TokenNotAuthenticated",
			message: "invalid bearer token",
			replies: review(`{"kind":"TokenReview","status":{"authenticated":false,"error":"invalid bearer token"}}`)},
		{name: "not authenticated", code: 403, reason: "Forbidden", cause: "TokenNotAuthenticated",
			replies: review(`{"kind":"TokenReview","status":{"authenticated":false}}`)},
		{name: "wrong audience", code: 403, reason: "Forbidden", cause: "AudienceMismatch",
			replies: review(`{"kind":"TokenReview","status":{"authenticated":true,"audiences":["kube-apiserver"],
				"user":{"username":"system:serviceaccount:krateo-system:cdc"}}}`)},
		{name: "not a service account", code: 403, reason: "Forbidden", cause: "NotAServiceAccount",
			replies: review(`{"kind":"TokenReview","status":{"authenticated":true,"audiences":["authn"],"user":{"username":"alice"}}}`)},
		{name: "no mapping", replies: mappings(mappingList()), code: 403, reason: "Forbidden", cause: "NoMapping"},
		{name: "ambiguous mapping", code: 403, reason: "Forbidden", cause: "AmbiguousMapping",
			replies: mappings(mappingList(mappingCdc, strings.Replace(mappingCdc, "cdc-identity", "cdc-other", 1)))},

		// Failures of authn.
		{name: "token review call fails", replies: failing(true), code: 500, reason: "InternalError", cause: "TokenReviewFailed"},
		{name: "mapping lookup fails", replies: failing(false), code: 500, reason: "InternalError", cause: "MappingLookupFailed"},
		{name: "clientconfig issuance fails", generateErr: errors.New("csr not approved"), minted: true,
			code: 500, reason: "InternalError", cause: "IssuanceFailed", message: "csr not approved"},
		{name: "access token signing fails", keyID: "-", minted: true,
			code: 500, reason: "InternalError", cause: "IssuanceFailed", message: "issuing access token"},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			replies := tc.replies
			if replies == (apiReplies{}) {
				replies = defaultReplies()
			}
			srv := fakeAPIServer(t, replies)
			defer srv.Close()

			// An empty key ID makes the token signer refuse; "-" selects it.
			keyID := "k"
			if tc.keyID == "-" {
				keyID = ""
			}
			gen := &fakeGenerator{err: tc.generateErr}
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{
				KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: keyID,
			})

			req := httptest.NewRequest(http.MethodPost, Path, nil)
			if !tc.noBearer {
				req.Header.Set("Authorization", "Bearer projected-sa-token")
			}
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			var out struct {
				Kind    string `json:"kind"`
				Code    int    `json:"code"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
				Details struct {
					Causes []struct {
						Reason  string `json:"reason"`
						Message string `json:"message"`
					} `json:"causes"`
				} `json:"details"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
			assert.Equal(t, "Status", out.Kind)
			assert.Equal(t, tc.code, out.Code, "the body's code matches the HTTP status")
			assert.Equal(t, tc.reason, out.Reason, "the top-level reason stays generic")
			require.Len(t, out.Details.Causes, 1)
			assert.Equal(t, tc.cause, out.Details.Causes[0].Reason)
			assert.NotEmpty(t, out.Details.Causes[0].Message)
			if tc.message != "" {
				assert.Contains(t, out.Details.Causes[0].Message, tc.message)
			}
			assert.NotContains(t, rec.Body.String(), "accessToken", "no token on failure")
			if tc.minted {
				assert.Len(t, gen.calls, 1, "issuance was attempted for the authenticated caller")
			} else {
				assert.Empty(t, gen.calls, "nothing is minted for a refused caller")
			}
		})
	}
}

// A refused caller is logged at warn, authn's own failure at error, each with
// its cause (status.LogFailure).
func TestHandlerLogLevels(t *testing.T) {
	noMapping := defaultReplies()
	noMapping.mappings = mappingList()
	lookupFails := defaultReplies()
	lookupFails.mappingsCode = http.StatusInternalServerError

	cases := []struct {
		name    string
		replies apiReplies
		level   string
		cause   string
	}{
		{name: "no mapping", replies: noMapping, level: "warn", cause: "NoMapping"},
		{name: "mapping lookup fails", replies: lookupFails, level: "error", cause: "MappingLookupFailed"},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			srv := fakeAPIServer(t, tc.replies)
			defer srv.Close()
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{
				KubeconfigGenerator: &fakeGenerator{}, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k",
			})

			var buf bytes.Buffer
			req := httptest.NewRequest(http.MethodPost, Path, nil)
			req = req.WithContext(zerolog.New(&buf).WithContext(req.Context()))
			req.Header.Set("Authorization", "Bearer projected-sa-token")
			route.Handler().ServeHTTP(httptest.NewRecorder(), req)

			var line map[string]any
			for _, l := range bytes.Split(buf.Bytes(), []byte("\n")) {
				var m map[string]any
				if json.Unmarshal(l, &m) == nil && m["message"] == "serviceaccount auth failed" {
					line = m
				}
			}
			require.NotNil(t, line, buf.String())
			assert.Equal(t, tc.level, line["level"])
			assert.Equal(t, tc.cause, line["cause"])
			assert.NotEmpty(t, line["error"])
		})
	}
}
