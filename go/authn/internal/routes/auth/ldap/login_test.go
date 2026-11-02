package ldap

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

type fakeGenerator struct {
	calls int
	err   error
}

func (g *fakeGenerator) Generate(storage.Strategy, userinfo.Info) ([]byte, time.Time, error) {
	g.calls++
	if g.err != nil {
		return nil, time.Time{}, g.err
	}
	return []byte(`{}`), time.Now().Add(time.Hour), nil
}

func (g *fakeGenerator) GenerateStepUp(storage.Strategy, userinfo.Info, time.Duration) (time.Time, error) {
	panic("ldap login never issues a step-up credential")
}

const (
	adminDN, aliceDN = "cn=admin,dc=example", "uid=alice,dc=example"
	fakeDialURL      = "ldap://ldap.example:389"
)

// fakeLDAP is the LDAP server as the login sees it. Its errors are the
// *ldap.Error values go-ldap builds from a server's result code. Methods the
// login doesn't call are left to the nil embedded Client and panic.
type fakeLDAP struct {
	ldap.Client
	startTLS  error
	adminBind error
	userBind  error
	search    error
	entries   int
	searches  int
}

func (f *fakeLDAP) Close() error               { return nil }
func (f *fakeLDAP) StartTLS(*tls.Config) error { return f.startTLS }
func (f *fakeLDAP) Bind(dn, password string) error {
	switch dn {
	case adminDN:
		return f.adminBind
	case aliceDN:
		return f.userBind
	}
	return fmt.Errorf("unexpected bind as %q", dn)
}

func (f *fakeLDAP) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searches++
	if f.search != nil {
		return nil, f.search
	}
	if f.searches > 1 { // the group search
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=devs,dc=example", map[string][]string{"cn": {"devs"}})}}, nil
	}
	res := &ldap.SearchResult{}
	for i := 0; i < f.entries; i++ {
		res.Entries = append(res.Entries, ldap.NewEntry(aliceDN, map[string][]string{"uid": {"alice"}, "cn": {"Alice"}}))
	}
	return res, nil
}

var (
	keyOnce sync.Once
	key     *rsa.PrivateKey
)

// testKey is one signing key for every test: generating one per case is slow.
func testKey(t *testing.T) *rsa.PrivateKey {
	keyOnce.Do(func() {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
	})
	return key
}

func ldapErr(code uint16) error { return ldap.NewError(code, errors.New("from the server")) }

// fakeAPIServer serves the LDAPConfig "corp" (dialing dialURL, with StartTLS)
// and its bind Secret, each answering with the given code.
func fakeAPIServer(t *testing.T, configCode, secretCode int, dialURL string) *httptest.Server {
	t.Helper()
	fail := func(w http.ResponseWriter, code int) {
		w.WriteHeader(code)
		reason := map[int]string{404: "NotFound"}[code]
		fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":%q,"message":"boom","code":%d}`, reason, code)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/ldap.authn.krateo.io/v1alpha1/namespaces/krateo-system/ldapconfigs/corp":
			if configCode != http.StatusOK {
				fail(w, configCode)
				return
			}
			fmt.Fprintf(w, `{"apiVersion":"ldap.authn.krateo.io/v1alpha1","kind":"LDAPConfig","metadata":{"name":"corp","namespace":"krateo-system"},
				"spec":{"dialURL":%q,"baseDN":"dc=example","bindDN":%q,"tls":true,
				"bindSecret":{"name":"ldap-bind","namespace":"krateo-system","key":"password"}}}`, dialURL, adminDN)
		case "/api/v1/namespaces/krateo-system/secrets/ldap-bind":
			if secretCode != http.StatusOK {
				fail(w, secretCode)
				return
			}
			fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"ldap-bind","namespace":"krateo-system"},"data":{"password":%q}}`,
				base64.StdEncoding.EncodeToString([]byte("bind-secret")))
		default:
			fail(w, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type result struct {
	code    int
	cause   string
	level   string
	minted  int
	tokened bool
}

func login(t *testing.T, name string, configCode, secretCode int, srvLDAP *fakeLDAP, gen *fakeGenerator, realDial bool) result {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	if !realDial {
		orig := dial
		dial = func(url string) (ldap.Client, error) {
			if url != fakeDialURL {
				return nil, fmt.Errorf("unexpected dial to %q", url)
			}
			return srvLDAP, nil
		}
		t.Cleanup(func() { dial = orig })
	}
	dialURL := fakeDialURL
	if realDial {
		dialURL = "ldap://127.0.0.1:1" // nothing listens there
	}
	srv := fakeAPIServer(t, configCode, secretCode, dialURL)
	route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: testKey(t), JwtKeyID: "k"})

	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, Path+"?name="+name, strings.NewReader(`{"username":"alice","password":"pw"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(zerolog.New(&buf).WithContext(req.Context()))
	rec := httptest.NewRecorder()
	route.Handler().ServeHTTP(rec, req)

	res := result{code: rec.Code, minted: gen.calls, tokened: strings.Contains(rec.Body.String(), "accessToken")}
	if rec.Code == http.StatusOK {
		return res
	}
	var out struct {
		Code    int `json:"code"`
		Details struct {
			Causes []struct {
				Reason string `json:"reason"`
			} `json:"causes"`
		} `json:"details"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	require.Equal(t, rec.Code, out.Code, "the body's code matches the HTTP status")
	require.Len(t, out.Details.Causes, 1, rec.Body.String())
	res.cause = out.Details.Causes[0].Reason

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	var line struct {
		Level string `json:"level"`
		Cause string `json:"cause"`
	}
	require.NoError(t, json.Unmarshal(lines[len(lines)-1], &line), buf.String())
	require.Equal(t, res.cause, line.Cause, "the log line carries the cause")
	res.level = line.Level
	return res
}

func TestLoginFailureCauses(t *testing.T) {
	cases := []struct {
		name        string
		config      string
		configCode  int
		secretCode  int
		ldap        *fakeLDAP
		realDial    bool
		generateErr error
		code        int
		cause       string
		level       string
	}{
		// Refusals of the caller, and the not-found answers.
		{name: "unknown LDAPConfig", configCode: 404, code: 404, cause: "LDAPConfigNotFound", level: "warn"},
		{name: "unusable LDAPConfig name", config: "..", code: 404, cause: "LDAPConfigNotFound", level: "warn"},
		{name: "no such user", ldap: &fakeLDAP{entries: 0}, code: 403, cause: "InvalidCredentials", level: "warn"},
		{name: "ambiguous user", ldap: &fakeLDAP{entries: 2}, code: 300, cause: "AmbiguousUser", level: "warn"},
		{name: "wrong password", ldap: &fakeLDAP{entries: 1, userBind: ldapErr(ldap.LDAPResultInvalidCredentials)},
			code: 403, cause: "InvalidCredentials", level: "warn"},
		{name: "disabled account", ldap: &fakeLDAP{entries: 1, userBind: ldapErr(ldap.LDAPResultUnwillingToPerform)},
			code: 403, cause: "InvalidCredentials", level: "warn"},
		{name: "empty password", ldap: &fakeLDAP{entries: 1, userBind: ldapErr(ldap.ErrorEmptyPassword)},
			code: 403, cause: "InvalidCredentials", level: "warn"},

		// Failures of authn.
		{name: "LDAPConfig lookup fails", configCode: 500, code: 500, cause: "LDAPConfigLookupFailed", level: "error"},
		{name: "bind secret lookup fails", secretCode: 500, code: 500, cause: "LDAPConfigLookupFailed", level: "error"},
		{name: "server unreachable", realDial: true, code: 500, cause: "LDAPUnavailable", level: "error"},
		{name: "StartTLS fails", ldap: &fakeLDAP{startTLS: ldapErr(ldap.LDAPResultProtocolError)}, code: 500, cause: "LDAPUnavailable", level: "error"},
		{name: "connection lost", ldap: &fakeLDAP{adminBind: ldapErr(ldap.ErrorNetwork)}, code: 500, cause: "LDAPUnavailable", level: "error"},
		{name: "bind DN refused", ldap: &fakeLDAP{adminBind: ldapErr(ldap.LDAPResultInvalidCredentials)}, code: 500, cause: "LDAPBindFailed", level: "error"},
		{name: "user bind fails server-side", ldap: &fakeLDAP{entries: 1, userBind: ldapErr(ldap.LDAPResultUnavailable)},
			code: 500, cause: "LDAPBindFailed", level: "error"},
		{name: "base DN doesn't exist", ldap: &fakeLDAP{search: ldapErr(ldap.LDAPResultNoSuchObject)}, code: 500, cause: "LDAPSearchFailed", level: "error"},
		{name: "clientconfig issuance fails", ldap: &fakeLDAP{entries: 1}, generateErr: errors.New("csr not approved"),
			code: 500, cause: "IssuanceFailed", level: "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "corp"
			if tc.config != "" {
				name = tc.config
			}
			if tc.configCode == 0 {
				tc.configCode = 200
			}
			if tc.secretCode == 0 {
				tc.secretCode = 200
			}
			gen := &fakeGenerator{err: tc.generateErr}
			got := login(t, name, tc.configCode, tc.secretCode, tc.ldap, gen, tc.realDial)

			assert.Equal(t, tc.code, got.code)
			assert.Equal(t, tc.cause, got.cause)
			assert.Equal(t, tc.level, got.level)
			assert.False(t, got.tokened, "no token on failure")
			if tc.generateErr == nil {
				assert.Zero(t, got.minted, "nothing is minted for a failed login")
			}
		})
	}
}

// An unknown user, a wrong password and an empty password get the very same
// response, so a caller can't probe which users exist. Only the log tells
// them apart.
func TestInvalidCredentialsAreIndistinguishable(t *testing.T) {
	attempt := func(srvLDAP *fakeLDAP) (*httptest.ResponseRecorder, string) {
		t.Setenv("POD_NAMESPACE", "krateo-system")
		orig := dial
		dial = func(string) (ldap.Client, error) { return srvLDAP, nil }
		defer func() { dial = orig }()
		srv := fakeAPIServer(t, 200, 200, fakeDialURL)
		route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: &fakeGenerator{}, JwtDuration: time.Hour, JwtPrivateKey: testKey(t), JwtKeyID: "k"})

		var buf bytes.Buffer
		req := httptest.NewRequest(http.MethodPost, Path+"?name=corp", strings.NewReader(`{"username":"alice","password":"pw"}`))
		req = req.WithContext(zerolog.New(&buf).WithContext(req.Context()))
		rec := httptest.NewRecorder()
		route.Handler().ServeHTTP(rec, req)

		lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
		var line struct {
			Level  string `json:"level"`
			Reason string `json:"reason"`
		}
		require.NoError(t, json.Unmarshal(lines[len(lines)-1], &line), buf.String())
		assert.Equal(t, "warn", line.Level)
		return rec, line.Reason
	}

	unknown, unknownWhy := attempt(&fakeLDAP{entries: 0})
	wrong, wrongWhy := attempt(&fakeLDAP{entries: 1, userBind: ldapErr(ldap.LDAPResultInvalidCredentials)})
	empty, emptyWhy := attempt(&fakeLDAP{entries: 1, userBind: ldapErr(ldap.ErrorEmptyPassword)})

	require.Equal(t, http.StatusForbidden, wrong.Code)
	assert.Equal(t, wrong.Code, unknown.Code)
	assert.Equal(t, wrong.Code, empty.Code)
	assert.Equal(t, wrong.Header(), unknown.Header())
	assert.Equal(t, wrong.Body.String(), unknown.Body.String(), "byte-identical bodies")
	assert.Equal(t, wrong.Body.String(), empty.Body.String(), "byte-identical bodies")
	assert.NotContains(t, wrong.Body.String(), "LDAP Result Code")

	assert.Contains(t, unknownWhy, "no users found")
	assert.Contains(t, wrongWhy, "Invalid Credentials")
	assert.Contains(t, emptyWhy, "Empty password")
}

func TestLoginSucceeds(t *testing.T) {
	gen := &fakeGenerator{}
	got := login(t, "corp", 200, 200, &fakeLDAP{entries: 1}, gen, false)
	assert.Equal(t, http.StatusOK, got.code)
	assert.Equal(t, 1, got.minted)
	assert.True(t, got.tokened)
}
