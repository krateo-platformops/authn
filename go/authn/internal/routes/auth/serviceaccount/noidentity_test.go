package serviceaccount

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// sentinelSA is the TokenReview username of a sentinel ServiceAccount.
const sentinelSA = "system:serviceaccount:" + logtest.Marker + "-ns:" + logtest.User

func sentinelReview(username string) string {
	return fmt.Sprintf(`{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
		"status":{"authenticated":true,"audiences":["authn"],"user":{"username":%q}}}`, username)
}

func sentinelMapping(name string) string {
	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":"krateo-system","uid":"0b1f6c1e"},
		"spec":{"serviceAccountRef":{"namespace":"%s-ns","name":%q},"groups":["%s-group"],"displayName":"%s Name"}}`,
		name, logtest.Marker, logtest.User, logtest.Marker, logtest.Marker)
}

// sentinelAPIServer answers the TokenReview and the mapping list. A failed
// list answers as the apiserver does, naming who asked.
func sentinelAPIServer(t *testing.T, review string, mappingsCode int, mappings string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			_, _ = w.Write([]byte(review))
		case "/apis/serviceaccount.authn.krateo.io/v1alpha1/namespaces/krateo-system/serviceaccounts":
			w.WriteHeader(mappingsCode)
			if mappingsCode != http.StatusOK {
				fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":%d,
					"message":"serviceaccounts is forbidden: User \"%s\" cannot list"}`, mappingsCode, sentinelSA)
				return
			}
			_, _ = w.Write([]byte(mappings))
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// No log line of a serviceaccount login names the caller, whether it signs in,
// is refused or fails: not its ServiceAccount, its mapping (the username), its
// groups, nor the apiserver's verdict on its token, which the caller is still
// answered (Diego, 2026-11-12).
func TestServiceAccountLoginLogsNoIdentity(t *testing.T) {
	one := mappingList(sentinelMapping(logtest.User))
	verdict := fmt.Sprintf(`[invalid bearer token, serviceaccounts \"%s\" not found]`, logtest.User)
	cases := []struct {
		name         string
		review       string
		mappingsCode int
		mappings     string
		generateErr  error
		code         int
		answered     string
	}{
		{name: "success", code: 200},
		{name: "token not authenticated", review: `{"kind":"TokenReview","status":{"authenticated":false,"error":"` + verdict + `"}}`,
			code: 403, answered: logtest.User},
		{name: "wrong audience", review: strings.Replace(sentinelReview(sentinelSA), `["authn"]`, `["kube-apiserver"]`, 1), code: 403},
		{name: "not a service account", review: sentinelReview(logtest.User), code: 403},
		{name: "malformed service account", review: sentinelReview("system:serviceaccount:" + logtest.User), code: 403},
		{name: "no mapping", mappings: mappingList(), code: 403},
		{name: "ambiguous mapping", mappings: mappingList(sentinelMapping(logtest.User), sentinelMapping(logtest.User+"-2")), code: 403},
		{name: "mapping lookup fails", mappingsCode: 403, code: 500},
		{name: "name guard refuses", code: 403, generateErr: kubeconfig.Refused(kubeconfig.RefusalClaimed,
			status.RefusedPrivately(status.CauseUsernameUnavailable, errors.New("the username isn't available to this identity"),
				errors.New("the username is claimed by another identity")))},
		{name: "issuance fails", code: 500, generateErr: errors.New("creating the credential Secret: Forbidden (403)")},
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			if tc.review == "" {
				tc.review = sentinelReview(sentinelSA)
			}
			if tc.mappingsCode == 0 {
				tc.mappingsCode = http.StatusOK
			}
			if tc.mappings == "" {
				tc.mappings = one
			}
			srv := sentinelAPIServer(t, tc.review, tc.mappingsCode, tc.mappings)
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: &fakeGenerator{err: tc.generateErr},
				JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})

			req, logs := logtest.Request(httptest.NewRequest(http.MethodPost, Path, nil))
			req.Header.Set("Authorization", "Bearer projected-sa-token")
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			if tc.answered != "" {
				assert.Contains(t, rec.Body.String(), tc.answered, "the caller is answered the apiserver's verdict")
			}
			logtest.NoIdentity(t, logs)
		})
	}
}
