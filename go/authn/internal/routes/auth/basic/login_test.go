package basic

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	panic("basic login never issues a step-up credential")
}

// reply is one canned apiserver answer: a status code and, for 200, a body.
type reply struct {
	code int
	body string
}

const (
	userAdmin = `{"apiVersion":"basic.authn.krateo.io/v1alpha1","kind":"User","metadata":{"name":"admin","namespace":"krateo-system"},
		"spec":{"displayName":"Admin","groups":["admins"],"passwordRef":{"name":"admin-password","namespace":"krateo-system","key":"password"}}}`
)

func secretWith(key, val string) string {
	return fmt.Sprintf(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"admin-password","namespace":"krateo-system"},"data":{%q:%q}}`,
		key, base64.StdEncoding.EncodeToString([]byte(val)))
}

// fakeAPIServer answers the two reads of a basic login: the User "admin" and
// its password Secret. Any other User is not found.
func fakeAPIServer(t *testing.T, user, secret reply) *httptest.Server {
	t.Helper()
	write := func(w http.ResponseWriter, rep reply, what string) {
		w.WriteHeader(rep.code)
		if rep.code == http.StatusOK {
			_, _ = w.Write([]byte(rep.body))
			return
		}
		reason := "InternalError"
		if rep.code == http.StatusNotFound {
			reason = "NotFound"
		}
		fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":%q,"message":"%s: boom","code":%d}`, reason, what, rep.code)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/basic.authn.krateo.io/v1alpha1/namespaces/krateo-system/users/admin":
			write(w, user, `users "admin"`)
		case "/api/v1/namespaces/krateo-system/secrets/admin-password":
			write(w, secret, `secrets "admin-password"`)
		default:
			write(w, reply{code: http.StatusNotFound}, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type logged struct {
	Level string `json:"level"`
	Cause string `json:"cause"`
}

// Every failure is a Status whose code says whose failure it is and whose
// details.causes[0].reason names it; it is logged at warn when the caller is
// refused and at error when authn failed.
func TestLoginFailureCauses(t *testing.T) {
	user := reply{code: http.StatusOK, body: userAdmin}
	password := reply{code: http.StatusOK, body: secretWith("password", "s3cret")}

	cases := []struct {
		name        string
		noAuth      bool
		username    string
		password    string
		user        reply
		secret      reply
		generateErr error
		code        int
		cause       string
		level       string
	}{
		// Refusals of the caller.
		{name: "no credentials", noAuth: true, code: 401, cause: "MissingCredentials"},
		{name: "unknown user", username: "bob", code: 403, cause: "InvalidCredentials", level: "warn"},
		{name: "unusable user name", username: "../admin", code: 403, cause: "InvalidCredentials", level: "warn"},
		{name: "empty user name", username: "-", code: 403, cause: "InvalidCredentials", level: "warn"},
		{name: "wrong password", password: "guess", code: 403, cause: "InvalidCredentials", level: "warn"},

		// Failures of authn.
		{name: "user lookup fails", user: reply{code: 500}, code: 500, cause: "UserLookupFailed", level: "error"},
		{name: "password secret missing", secret: reply{code: 404}, code: 500, cause: "PasswordSecretMissing", level: "error"},
		{name: "password key missing", secret: reply{code: 200, body: secretWith("other", "s3cret")}, code: 500, cause: "PasswordSecretMissing", level: "error"},
		{name: "password lookup fails", secret: reply{code: 500}, code: 500, cause: "PasswordLookupFailed", level: "error"},
		{name: "clientconfig issuance fails", generateErr: errors.New("csr not approved"), code: 500, cause: "IssuanceFailed", level: "error"},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			if tc.user == (reply{}) {
				tc.user = user
			}
			if tc.secret == (reply{}) {
				tc.secret = password
			}
			srv := fakeAPIServer(t, tc.user, tc.secret)
			gen := &fakeGenerator{err: tc.generateErr}
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})

			var buf bytes.Buffer
			req := httptest.NewRequest(http.MethodGet, Path, nil)
			req = req.WithContext(zerolog.New(&buf).WithContext(req.Context()))
			if !tc.noAuth {
				username, pwd := "admin", "s3cret"
				switch tc.username {
				case "":
				case "-":
					username = ""
				default:
					username = tc.username
				}
				if tc.password != "" {
					pwd = tc.password
				}
				req.SetBasicAuth(username, pwd)
			}
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			var out struct {
				Kind    string `json:"kind"`
				Code    int    `json:"code"`
				Details struct {
					Causes []struct {
						Reason string `json:"reason"`
					} `json:"causes"`
				} `json:"details"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
			assert.Equal(t, "Status", out.Kind)
			assert.Equal(t, tc.code, out.Code)
			require.Len(t, out.Details.Causes, 1)
			assert.Equal(t, tc.cause, out.Details.Causes[0].Reason)
			assert.NotContains(t, rec.Body.String(), "accessToken")
			if tc.noAuth {
				assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))
			}
			if tc.generateErr == nil {
				assert.Zero(t, gen.calls, "nothing is minted for a failed login")
			}

			if tc.level != "" {
				var line logged
				require.NoError(t, json.Unmarshal(lastLine(buf.Bytes()), &line), buf.String())
				assert.Equal(t, tc.level, line.Level)
				assert.Equal(t, tc.cause, line.Cause)
			}
		})
	}
}

func TestLoginSucceeds(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := fakeAPIServer(t, reply{code: 200, body: userAdmin}, reply{code: 200, body: secretWith("password", "s3cret")})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	gen := &fakeGenerator{}
	route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})

	req := httptest.NewRequest(http.MethodGet, Path, nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	route.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, gen.calls)
	assert.Contains(t, rec.Body.String(), "accessToken")
}

func lastLine(b []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	return lines[len(lines)-1]
}
