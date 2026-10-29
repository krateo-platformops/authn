package encode

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenDuration(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		requested time.Duration
		notAfter  time.Time
		want      time.Duration
	}{
		{
			name:      "no certificate leaves the request untouched",
			requested: time.Hour * 24,
			want:      time.Hour * 24,
		},
		{
			name:      "no request falls back to the default",
			requested: 0,
			want:      DefaultJwtDuration,
		},
		{
			// The signer honoured the request: nothing to clamp.
			name:      "certificate outlives the request",
			requested: time.Hour * 24,
			notAfter:  now.Add(time.Hour * 720),
			want:      time.Hour * 24,
		},
		{
			// The case that motivates the clamp: the signer's CA had two hours
			// left, so the 24h session would have outlived its credential.
			name:      "truncated certificate bounds the session",
			requested: time.Hour * 24,
			notAfter:  now.Add(time.Hour * 2),
			want:      time.Hour * 2,
		},
		{
			name:      "an unset request is clamped too",
			requested: 0,
			notAfter:  now.Add(time.Minute * 30),
			want:      time.Minute * 30,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tokenDuration(tc.requested, tc.notAfter)
			// time.Until moves between the table and the call.
			assert.InDelta(t, tc.want, got, float64(time.Second))
		})
	}
}

// A session must never outlive the credential it was issued with — assert it on
// the token that actually goes over the wire, not just on the helper.
func TestSuccessClampsTokenToCertificate(t *testing.T) {
	notAfter := time.Now().Add(time.Hour * 2)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	require.NoError(t, Success(rec, []byte(`{"kind":"Config"}`), &Extras{
		UserInfo:      userinfo.NewDefaultUser("alice", "1", []string{"devs"}, userinfo.Extensions{}),
		JwtDuration:   time.Hour * 24,
		JwtPrivateKey: key,
		JwtKeyID:      "test-key",
		CertNotAfter:  notAfter,
	}))
	require.Equal(t, http.StatusOK, rec.Code)

	var out struct {
		AccessToken string `json:"accessToken"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotEmpty(t, out.AccessToken)

	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(out.AccessToken, claims)
	require.NoError(t, err)

	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.WithinDuration(t, notAfter, exp.Time, time.Second*2,
		"the token must expire with the certificate, not 24h later")
}

// A token that cannot be signed must leave the response untouched, so the
// handler can still answer with a failure instead of an empty 200.
func TestSuccessWritesNothingWhenSigningFails(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	err = Success(rec, nil, &Extras{
		UserInfo:      userinfo.NewDefaultUser("cdc", "1", []string{"g"}, userinfo.Extensions{}),
		JwtDuration:   time.Hour,
		JwtPrivateKey: key,
		JwtKeyID:      "", // the signer refuses an empty key ID
	})
	require.Error(t, err)
	assert.False(t, rec.Flushed)
	assert.Empty(t, rec.Header())
	assert.Zero(t, rec.Body.Len())
}
