package basic

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
// comparison, so the comparison doesn't tell them apart. (A known user also
// costs a Secret read; see docs/gotchas.md.)
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
