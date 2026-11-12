package usernames

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// sentinelCaller is the caller's ServiceAccount, its mapping named after it,
// both carrying logtest's marker.
const sentinelCaller = "system:serviceaccount:krateo-system:" + logtest.Marker + "-controller"

func sentinelMappings(spec string) string {
	return `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[` +
		`{"metadata":{"name":"` + logtest.Marker + `-controller","namespace":"krateo-system"},"spec":{` +
		`"serviceAccountRef":{"namespace":"krateo-system","name":"` + logtest.Marker + `-controller"}` + spec + `}}]}`
}

// sentinelAPIServer answers the TokenReview and the mapping list, and refuses
// the session Secret's read with the apiserver's own Forbidden, which names
// the Secret, and so the user.
func sentinelAPIServer(t *testing.T, mappings string) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
			_, _ = w.Write([]byte(review(sentinelCaller)))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			_, _ = w.Write([]byte(mappings))
		case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/krateo-system/secrets/"):
			name := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/krateo-system/secrets/")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403,` +
				`"message":"secrets \"` + name + `\" is forbidden: User \"` + sentinelCaller + `\" cannot get resource \"secrets\""}`))
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// No log line of a check names the caller or the name asked about, whatever
// the outcome: the audit record carries both (Diego, 2026-11-12). The failed
// lookup goes through the real cluster lookup, so it's the apiserver's own
// answer, naming the Secret, that must not reach the log.
func TestCheckLogsNoIdentity(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"username": logtest.User})
	for _, tc := range []struct {
		name     string
		mappings string
		lookup   *lookup // nil: the cluster's own lookup, against the fake apiserver
		body     string
		code     int
	}{
		{"available", sentinelMappings(optedIn), &lookup{}, string(body), http.StatusOK},
		{"name_bound", sentinelMappings(optedIn), &lookup{bound: true}, string(body), http.StatusOK},
		{"not opted in", sentinelMappings(""), &lookup{}, string(body), http.StatusForbidden},
		{"no username", sentinelMappings(optedIn), &lookup{}, `{"user":"` + logtest.User + `"}`, http.StatusBadRequest},
		{"not JSON", sentinelMappings(optedIn), &lookup{}, logtest.User, http.StatusBadRequest},
		{"a lookup fails, its error naming the user", sentinelMappings(optedIn),
			&lookup{err: errors.New("reading User \"" + logtest.User + "\": timeout")}, string(body), http.StatusServiceUnavailable},
		{"the cluster refuses the Secret's read", sentinelMappings(optedIn), nil, string(body), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{Audience: "authn"}
			if tc.lookup != nil {
				opts.Lookup = tc.lookup
			}
			h := Route(sentinelAPIServer(t, tc.mappings), opts).Handler()
			req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer t")
			req, logs := logtest.Request(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			logtest.NoIdentity(t, logs)
		})
	}
}
