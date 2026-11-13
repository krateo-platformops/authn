package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// checkAPIServer authenticates the caller as an opted-in mapping and holds no
// Secret, User, mapping or binding for any name asked about.
func checkAPIServer(t *testing.T) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	const mappings = "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/tokenreviews"):
			_, _ = io.WriteString(w, `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,`+
				`"audiences":["authn"],"user":{"username":"system:serviceaccount:krateo-system:il"}}}`)
		case r.URL.Path == mappings:
			_, _ = io.WriteString(w, `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[`+
				`{"metadata":{"name":"il","namespace":"krateo-system"},"spec":{"serviceAccountRef":{"namespace":"krateo-system","name":"il"},`+
				`"usernameCheck":{"allowed":true}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/clusterrolebindings"):
			_, _ = io.WriteString(w, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBindingList","items":[]}`)
		case strings.HasSuffix(r.URL.Path, "/rolebindings"):
			_, _ = io.WriteString(w, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","items":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// routeOptions.Naming reaches /usernames/check and the record it writes, as
// main wires it: with exact names on, john.doe is available and its record
// names john.doe-clientconfig; off, it is invalid and names no Secret.
func TestInternalRoutesFollowTheNaming(t *testing.T) {
	rc := checkAPIServer(t)
	for _, tc := range []struct {
		naming    storage.Naming
		available bool
		reason    string
		secret    string
	}{
		{storage.Naming{Exact: true}, true, "", "john.doe-clientconfig"},
		{storage.Naming{}, false, "invalid", ""},
	} {
		ar, rec := auditlogtest.New(t)
		h := auditlog.Middleware(routes.Serve(buildInternalRoutes(routeOptions{RestConfig: rc, ServiceAccountAudience: "authn",
			Audit: ar, Naming: tc.naming}), testLogger()))
		req := httptest.NewRequest(http.MethodPost, "/usernames/check", strings.NewReader(`{"username":"john.doe"}`))
		req.Header.Set("Authorization", "Bearer t")
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		var out struct {
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
		}
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
		assert.Equal(t, tc.available, out.Available, "exact=%v", tc.naming.Exact)
		assert.Equal(t, tc.reason, out.Reason)
		assert.Equal(t, tc.secret, auditlogtest.String(rec.Only(t), "krateo.audit.object_ref.name"), "exact=%v", tc.naming.Exact)
	}
}
