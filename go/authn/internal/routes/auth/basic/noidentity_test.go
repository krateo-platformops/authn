package basic

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/logtest/gentest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// sentinelAPIServer answers a basic login of logtest.User the way the
// apiserver does: its errors name the object, which is named after the user.
func sentinelAPIServer(t *testing.T, user, secret reply) *httptest.Server {
	t.Helper()
	write := func(w http.ResponseWriter, rep reply, object string) {
		w.WriteHeader(rep.code)
		if rep.code == http.StatusOK {
			_, _ = w.Write([]byte(rep.body))
			return
		}
		reason := map[int]string{404: "NotFound", 403: "Forbidden"}[rep.code]
		if reason == "" {
			reason = "InternalError"
		}
		fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":%q,"message":"%s %s","code":%d}`,
			reason, object, reason, rep.code)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/basic.authn.krateo.io/v1alpha1/namespaces/krateo-system/users/" + logtest.User:
			write(w, user, `users.basic.authn.krateo.io \"`+logtest.User+`\"`)
		case "/api/v1/namespaces/krateo-system/secrets/" + logtest.User + "-password":
			write(w, secret, `secrets \"`+logtest.User+`-password\"`)
		default:
			write(w, reply{code: http.StatusNotFound}, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// No log line of a basic login names the user, whether it succeeds, is
// refused or fails: not the username, its User or Secret, its display name or
// its groups (Diego, 2026-11-12).
func TestBasicLoginLogsNoIdentity(t *testing.T) {
	sentinelUser := fmt.Sprintf(`{"apiVersion":"basic.authn.krateo.io/v1alpha1","kind":"User","metadata":{"name":%q,"namespace":"krateo-system"},
		"spec":{"displayName":"%s Display","groups":["%s-group"],"passwordRef":{"name":"%s-password","namespace":"krateo-system","key":"password"}}}`,
		logtest.User, logtest.Marker, logtest.Marker, logtest.User)
	noRef := fmt.Sprintf(`{"apiVersion":"basic.authn.krateo.io/v1alpha1","kind":"User","metadata":{"name":%q,"namespace":"krateo-system"},"spec":{}}`, logtest.User)
	secret := func(key string) string {
		return fmt.Sprintf(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"%s-password","namespace":"krateo-system"},"data":{%q:%q}}`,
			logtest.User, key, base64.StdEncoding.EncodeToString([]byte("s3cret")))
	}
	ok := reply{code: 200, body: sentinelUser}
	pwd := reply{code: 200, body: secret("password")}

	cases := []struct {
		name        string
		username    string
		password    string
		user        reply
		secret      reply
		generateErr error
		code        int
	}{
		{name: "success", code: 200},
		{name: "wrong password", password: "guess", code: 403},
		{name: "unknown user", user: reply{code: 404}, code: 403},
		{name: "unusable user name", username: logtest.User + "/..", code: 403},
		{name: "user lookup forbidden", user: reply{code: 403}, code: 500},
		{name: "user lookup fails", user: reply{code: 500}, code: 500},
		{name: "no passwordRef", user: reply{code: 200, body: noRef}, code: 500},
		{name: "password secret missing", secret: reply{code: 404}, code: 500},
		{name: "password lookup fails", secret: reply{code: 500}, code: 500},
		{name: "password key missing", secret: reply{code: 200, body: secret("other")}, code: 500},
		{name: "name guard refuses", code: 403, generateErr: kubeconfig.Refused(kubeconfig.RefusalClaimed,
			status.RefusedPrivately(status.CauseUsernameUnavailable, errors.New("the username isn't available to this identity"),
				errors.New("the username is claimed by another identity")))},
		{name: "issuance fails", code: 500, generateErr: errors.New("creating the CertificateSigningRequest: Forbidden (403)")},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			if tc.user == (reply{}) {
				tc.user = ok
			}
			if tc.secret == (reply{}) {
				tc.secret = pwd
			}
			if tc.username == "" {
				tc.username = logtest.User
			}
			if tc.password == "" {
				tc.password = "s3cret"
			}
			srv := sentinelAPIServer(t, tc.user, tc.secret)
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gentest.Generator{Generator: &fakeGenerator{err: tc.generateErr}, T: t},
				JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})

			req, logs := logtest.Request(httptest.NewRequest(http.MethodGet, Path, nil))
			req.SetBasicAuth(tc.username, tc.password)
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			if rec.Code == http.StatusOK {
				require.Contains(t, logs.String(), gentest.Line, "the route hands the generator its logger")
			}
			logtest.NoIdentity(t, logs)
		})
	}
}
