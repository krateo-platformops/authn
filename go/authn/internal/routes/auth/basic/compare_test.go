package basic

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

func TestComparePassword(t *testing.T) {
	assert.True(t, comparePassword("s3cret", []byte("s3cret")))
	for _, got := range []string{"", "s3cre", "s3cret ", "S3cret", "s3cret\x00"} {
		assert.False(t, comparePassword(got, []byte("s3cret")), "%q", got)
	}
	assert.False(t, comparePassword("x", nil))
	assert.True(t, comparePassword("", []byte{}), "an empty stored password matches only an empty one")
}

// A wrong password and an unknown user each cost exactly one constant-time
// comparison, so the comparison doesn't tell them apart. TestUnknownUserReadsTheDecoy
// covers the Secret read.
func TestUnknownUserCostsTheSameComparison(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := fakeAPIServer(t, reply{code: 200, body: userAdmin}, reply{code: 200, body: secretWith("password", "s3cret")})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	route := Login(&rest.Config{Host: srv.URL}, LoginOptions{KubeconfigGenerator: &fakeGenerator{}, JwtDuration: time.Hour, JwtPrivateKey: key, JwtKeyID: "k"})

	real := comparePassword
	t.Cleanup(func() { comparePassword = real })
	calls := 0
	comparePassword = func(got string, want []byte) bool { calls++; return real(got, want) }

	for _, who := range []string{"admin", "bob"} {
		calls = 0
		req := httptest.NewRequest(http.MethodGet, Path, nil)
		req.SetBasicAuth(who, "guess")
		rec := httptest.NewRecorder()
		route.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, who)
		assert.Equal(t, 1, calls, "%s: one comparison", who)
	}
}

// decoyAPIServer answers like fakeAPIServer, plus the decoy Secret, and counts
// the Secret reads.
func decoyAPIServer(t *testing.T, decoy reply) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/basic.authn.krateo.io/v1alpha1/namespaces/krateo-system/users/admin":
			_, _ = w.Write([]byte(userAdmin))
		case "/api/v1/namespaces/krateo-system/secrets/admin-password":
			reads.Add(1)
			_, _ = w.Write([]byte(secretWith("password", "s3cret")))
		case "/api/v1/namespaces/krateo-system/secrets/authn-basic-decoy":
			reads.Add(1)
			w.WriteHeader(decoy.code)
			_, _ = w.Write([]byte(decoy.body))
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","message":"%s","code":404}`, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &reads
}

func loginWithDecoy(t *testing.T, srv *httptest.Server, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	route := Login(&rest.Config{Host: srv.URL}, LoginOptions{
		KubeconfigGenerator: &fakeGenerator{},
		JwtDuration:         time.Hour,
		JwtPrivateKey:       key,
		JwtKeyID:            "k",
		DecoySecret:         &core.SecretKeySelector{Name: "authn-basic-decoy", Namespace: "krateo-system", Key: DecoyKey},
	})
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	req.SetBasicAuth(username, password)
	rec := httptest.NewRecorder()
	route.Handler().ServeHTTP(rec, req)
	return rec
}

// A known and an unknown user each cost one Secret read, so the Secret read
// doesn't tell them apart.
func TestUnknownUserReadsTheDecoy(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv, reads := decoyAPIServer(t, reply{code: 200, body: secretWith(DecoyKey, "decoy")})

	for _, who := range []string{"admin", "bob"} {
		reads.Store(0)
		rec := loginWithDecoy(t, srv, who, "guess")
		require.Equal(t, http.StatusForbidden, rec.Code, who)
		assert.Equal(t, int32(1), reads.Load(), "%s: one Secret read", who)
	}
}

// The decoy's value is in the chart, so it must admit nobody.
func TestDecoyValueAdmitsNobody(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv, _ := decoyAPIServer(t, reply{code: 200, body: secretWith(DecoyKey, "decoy")})

	rec := loginWithDecoy(t, srv, "bob", "decoy")
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// A decoy that can't be read must not change the answer: a 500 would tell a
// caller that the name is unknown.
func TestDecoyFailureStaysARefusal(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")
	for name, decoy := range map[string]reply{
		"missing":     {code: http.StatusNotFound, body: `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`},
		"unreadable":  {code: http.StatusInternalServerError, body: `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError","code":500}`},
		"no such key": {code: 200, body: secretWith("other", "x")},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := decoyAPIServer(t, decoy)
			known := loginWithDecoy(t, srv, "admin", "guess")
			unknown := loginWithDecoy(t, srv, "bob", "guess")
			assert.Equal(t, http.StatusForbidden, unknown.Code)
			assert.Equal(t, known.Body.String(), unknown.Body.String())
		})
	}
}
