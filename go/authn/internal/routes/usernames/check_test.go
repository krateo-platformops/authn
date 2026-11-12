package usernames

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const caller = "system:serviceaccount:krateo-system:identity-lifecycle-controller"

func review(user string) string {
	return `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"audiences":["authn"],"user":{"username":"` + user + `"}}}`
}

// mappings is the mapping list, the controller's mapping with spec as given.
func mappings(spec string) string {
	if spec == "" {
		return `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[]}`
	}
	return `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[` +
		`{"metadata":{"name":"identity-lifecycle-controller","namespace":"krateo-system"},"spec":{` +
		`"serviceAccountRef":{"namespace":"krateo-system","name":"identity-lifecycle-controller"}` + spec + `}}]}`
}

func apiserver(t *testing.T, tokenReview, mappingList string) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			_, _ = w.Write([]byte(tokenReview))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			_, _ = w.Write([]byte(mappingList))
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// lookup is the name guard's facts, as given.
type lookup struct {
	secret      *corev1.Secret
	provisioned bool
	bound       bool
	err         error
	reads       int
}

func (l *lookup) SessionSecret(context.Context, string) (*corev1.Secret, error) {
	l.reads++
	return l.secret, l.err
}
func (l *lookup) Secret(context.Context, string) (*corev1.Secret, error) { return l.secret, l.err }
func (l *lookup) Provisioned(context.Context, string) (bool, error) {
	l.reads++
	return l.provisioned, l.err
}
func (l *lookup) BoundAsUser(context.Context, string) (bool, error) {
	l.reads++
	return l.bound, l.err
}

const optedIn = `,"usernameCheck":{"allowed":true}`

func check(t *testing.T, rc *rest.Config, l *lookup, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := Route(rc, Options{Audience: "authn", Lookup: l}).Handler()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func cause(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Details struct {
			Causes []struct {
				Reason string `json:"reason"`
			} `json:"causes"`
		} `json:"details"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	require.Len(t, out.Details.Causes, 1, rec.Body.String())
	return out.Details.Causes[0].Reason
}

// An opted-in caller gets each reason, or available, as the guard decides it.
func TestCheck(t *testing.T) {
	rc := apiserver(t, review(caller), mappings(optedIn))
	claimed := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{storage.ClaimAnnotation: `["oidc","kc","9"]`}}}
	for _, tc := range []struct {
		name string
		user string
		l    lookup
		want Response
	}{
		{"available", "alice", lookup{}, Response{Available: true}},
		{"invalid", "Alice@Example", lookup{}, Response{Reason: "invalid"}},
		{"empty is checked, and invalid", "", lookup{}, Response{Reason: "invalid"}},
		{"reserved", "admin", lookup{}, Response{Reason: "reserved"}},
		{"name_claimed", "alice", lookup{secret: claimed}, Response{Reason: "name_claimed"}},
		{"name_held_legacy", "alice", lookup{secret: &corev1.Secret{}}, Response{Reason: "name_held_legacy"}},
		{"name_provisioned", "alice", lookup{provisioned: true}, Response{Reason: "name_provisioned"}},
		{"name_bound", "alice", lookup{bound: true}, Response{Reason: "name_bound"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"username": tc.user})
			rec := check(t, rc, &tc.l, "projected-sa-token", string(body))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			var got Response
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, tc.want, got)
			if !tc.want.Available {
				assert.NotContains(t, rec.Body.String(), `"available":true`)
			} else {
				assert.NotContains(t, rec.Body.String(), `"reason"`, "no reason when available")
			}
		})
	}
}

// Every refusal of the caller, and a check that can't complete, is a non-200
// with its cause, and none says the name is available.
func TestCheckRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		review   string
		mappings string
		bearer   string
		body     string
		l        lookup
		code     int
		cause    string
	}{
		{name: "no bearer", review: review(caller), mappings: mappings(optedIn), body: `{"username":"alice"}`, code: 401, cause: "MissingBearer"},
		{name: "token not authenticated", review: `{"kind":"TokenReview","status":{"authenticated":false}}`, mappings: mappings(optedIn),
			bearer: "t", body: `{"username":"alice"}`, code: 403, cause: "TokenNotAuthenticated"},
		{name: "not a service account", review: review("alice"), mappings: mappings(optedIn), bearer: "t", body: `{"username":"bob"}`, code: 403, cause: "NotAServiceAccount"},
		{name: "no mapping", review: review(caller), mappings: mappings(""), bearer: "t", body: `{"username":"alice"}`, code: 403, cause: "NoMapping"},
		{name: "a mapping that didn't opt in", review: review(caller), mappings: mappings(`,"delegation":{"allowed":true}`), bearer: "t",
			body: `{"username":"alice"}`, code: 403, cause: "UsernameCheckNotAllowed"},
		{name: "opted in with allowed false", review: review(caller), mappings: mappings(`,"usernameCheck":{"allowed":false}`), bearer: "t",
			body: `{"username":"alice"}`, code: 403, cause: "UsernameCheckNotAllowed"},
		{name: "no username", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `{}`, code: 400, cause: "MissingUsername"},
		{name: "not JSON", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `username=alice`, code: 400, cause: "InvalidRequestBody"},
		{name: "too big", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `{"username":"` + strings.Repeat("a", 5000) + `"}`, code: 400, cause: "InvalidRequestBody"},
		{name: "a lookup fails: fail closed", review: review(caller), mappings: mappings(optedIn), bearer: "t", body: `{"username":"alice"}`,
			l: lookup{err: errors.New("apiserver down")}, code: 503, cause: "UsernameCheckFailed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := check(t, apiserver(t, tc.review, tc.mappings), &tc.l, tc.bearer, tc.body)
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Equal(t, tc.cause, cause(t, rec))
			assert.NotContains(t, rec.Body.String(), `"available"`, "a refusal never answers availability")
			if tc.code != 503 {
				assert.Zero(t, tc.l.reads, "a refused caller learns nothing: the guard is never read")
			}
		})
	}
}
