package ldap

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/logtest/gentest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// No log line of an LDAP login names the user, whether it succeeds, is
// refused or fails: not the login name, its DN, its cn or mail, or its groups
// (Diego, 2026-11-12).
func TestLDAPLoginLogsNoIdentity(t *testing.T) {
	sentinelDN := "uid=" + logtest.User + ",dc=example"
	// A server's diagnostic message can name the DN: only its result code
	// may reach a log line.
	diag := func(code uint16) error { return ldap.NewError(code, errors.New("bind of "+sentinelDN+" refused")) }
	user := func(f fakeLDAP) *fakeLDAP {
		f.userDN, f.uid, f.mail = sentinelDN, logtest.User, logtest.Email
		f.groups = []*ldap.Entry{ldap.NewEntry("cn="+logtest.Marker+"-group,dc=example",
			map[string][]string{"cn": {logtest.Marker + "-group"}})}
		return &f
	}
	cases := []struct {
		name        string
		ldap        *fakeLDAP
		generateErr error
		code        int
	}{
		{name: "success", ldap: user(fakeLDAP{entries: 1}), code: 200},
		{name: "no such user", ldap: user(fakeLDAP{entries: 0}), code: 403},
		{name: "ambiguous user", ldap: user(fakeLDAP{entries: 2}), code: 300},
		{name: "wrong password", ldap: user(fakeLDAP{entries: 1, userBind: diag(ldap.LDAPResultInvalidCredentials)}), code: 403},
		{name: "user bind fails server-side", ldap: user(fakeLDAP{entries: 1, userBind: diag(ldap.LDAPResultUnavailable)}), code: 500},
		{name: "StartTLS fails", ldap: user(fakeLDAP{startTLS: diag(ldap.LDAPResultProtocolError)}), code: 500},
		{name: "the bind DN is refused", ldap: user(fakeLDAP{adminBind: diag(ldap.LDAPResultInvalidCredentials)}), code: 500},
		{name: "the connection is lost", ldap: user(fakeLDAP{adminBind: diag(ldap.ErrorNetwork)}), code: 500},
		{name: "the user search fails", ldap: user(fakeLDAP{search: diag(ldap.LDAPResultNoSuchObject)}), code: 500},
		{name: "group search fails", ldap: user(fakeLDAP{entries: 1, groupErr: diag(ldap.LDAPResultNoSuchObject)}), code: 500},
		{name: "name guard refuses", ldap: user(fakeLDAP{entries: 1}), code: 403, generateErr: kubeconfig.Refused(kubeconfig.RefusalBound,
			status.RefusedPrivately(status.CauseUsernameUnavailable, errors.New("the username isn't available to this identity"),
				errors.New("the username is already granted rights by a RoleBinding or ClusterRoleBinding")))},
		{name: "issuance fails", ldap: user(fakeLDAP{entries: 1}), code: 500, generateErr: errors.New("creating the CertificateSigningRequest: Forbidden (403)")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			orig := dial
			dial = func(string) (ldap.Client, error) { return tc.ldap, nil }
			t.Cleanup(func() { dial = orig })
			// The fake directory answers any bind of the user's DN.
			srv := fakeAPIServer(t, http.StatusOK, http.StatusOK, fakeDialURL, "")
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gentest.Generator{Generator: &fakeGenerator{err: tc.generateErr}, T: t},
				JwtDuration: time.Hour, JwtPrivateKey: testKey(t), JwtKeyID: "k"})

			body, err := json.Marshal(loginInfo{Username: logtest.User, Password: "pw"})
			require.NoError(t, err)
			req, logs := logtest.Request(httptest.NewRequest(http.MethodPost, Path+"?name=corp", bytes.NewReader(body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			if rec.Code == http.StatusOK {
				require.Contains(t, logs.String(), gentest.Line, "the route hands the generator its logger")
				logtest.NoIdentity(t, logs)
				return
			}
			logtest.NoIdentity(t, logs)
		})
	}
}
