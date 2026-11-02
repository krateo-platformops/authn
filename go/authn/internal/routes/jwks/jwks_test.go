package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEndpointServesUsableKey is the important correctness check: a token
// signed by authn must validate against the public key reconstructed purely
// from the JWKS the endpoint serves. This exercises the n/e base64url encoding.
func TestEndpointServesUsableKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "test-kid"

	// A token as authn would issue it.
	token, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
		Username:   "alice",
		Groups:     []string{"admins"},
		Duration:   time.Minute,
		KeyID:      kid,
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	// Fetch the JWKS from the endpoint.
	route := Endpoint(&privateKey.PublicKey, kid)
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	rec := httptest.NewRecorder()
	route.Handler()(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var set jwkSet
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &set))
	require.Len(t, set.Keys, 1)

	k := set.Keys[0]
	assert.Equal(t, "RSA", k.Kty)
	assert.Equal(t, "sig", k.Use)
	assert.Equal(t, "RS256", k.Alg)
	assert.Equal(t, kid, k.Kid)

	// Reconstruct the public key from the JWKS n/e and validate the token.
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	require.NoError(t, err)
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	require.NoError(t, err)

	reconstructed := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	info, err := jwtutil.Validate(reconstructed, token)
	require.NoError(t, err)
	assert.Equal(t, "alice", info.Username)
	assert.ElementsMatch(t, []string{"admins"}, info.Groups)
}

// TestEndpointIsConsumableByJWKSKeySource closes the cross-repo contract loop.
// The test above reconstructs the key by hand; this one drives authn's real
// endpoint through the SAME client its consumers use (plumbing's
// jwtutil.JWKSKeySource, which snowplow wires against this endpoint instead of
// mounting a public-key Secret). If the document authn serves and the parser
// consumers use ever disagree — field names, base64 variant, kid matching — this
// fails here rather than as a 503 in a cluster.
func TestEndpointIsConsumableByJWKSKeySource(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "krateo-authn-key-1"

	// Serve authn's real JWKS route at its real path.
	route := Endpoint(&privateKey.PublicKey, kid)
	mux := http.NewServeMux()
	mux.HandleFunc(route.Pattern(), route.Handler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A consumer resolves the key exactly as snowplow does.
	keys := jwtutil.NewJWKSKeySource(jwtutil.JWKSURL(srv.URL))

	token, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
		Username:   "alice",
		Groups:     []string{"admins"},
		Duration:   time.Minute,
		KeyID:      kid,
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	info, err := jwtutil.ValidateWithKeySource(keys, token)
	require.NoError(t, err, "a token authn signed must verify against the JWKS authn publishes")
	assert.Equal(t, "alice", info.Username)
	assert.ElementsMatch(t, []string{"admins"}, info.Groups)

	// authn's advertised path is the one the client derives from a base URL.
	assert.Equal(t, Path, jwtutil.DefaultJWKSPath,
		"authn's JWKS path must match the path consumers derive from authn's base URL")
}

// A key rotation keeps tokens signed with the retired key valid: the JWKS
// publishes it next to the current key, and a consumer using plumbing's
// JWKSKeySource verifies tokens signed with either. A key that isn't published
// verifies nothing.
func TestRotationKeepsTokensSignedWithThePreviousKeyValid(t *testing.T) {
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	retiredLongAgo, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	route := Endpoint(&newKey.PublicKey, "key-2", Key{KID: "key-1", Pub: &oldKey.PublicKey})
	mux := http.NewServeMux()
	mux.HandleFunc(route.Pattern(), route.Handler())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	keys := jwtutil.NewJWKSKeySource(jwtutil.JWKSURL(srv.URL))

	sign := func(k *rsa.PrivateKey, kid, user string) string {
		tok, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
			Username: user, Groups: []string{"devs"}, Duration: time.Minute, KeyID: kid, PrivateKey: k,
		})
		require.NoError(t, err)
		return tok
	}

	info, err := jwtutil.ValidateWithKeySource(keys, sign(newKey, "key-2", "after"))
	require.NoError(t, err, "a token signed with the current key verifies")
	assert.Equal(t, "after", info.Username)

	info, err = jwtutil.ValidateWithKeySource(keys, sign(oldKey, "key-1", "before"))
	require.NoError(t, err, "a token signed before the rotation still verifies")
	assert.Equal(t, "before", info.Username)

	_, err = jwtutil.ValidateWithKeySource(keys, sign(retiredLongAgo, "key-0", "gone"))
	assert.Error(t, err, "a key no longer published verifies nothing")

	_, err = jwtutil.ValidateWithKeySource(keys, sign(oldKey, "key-2", "forged"))
	assert.Error(t, err, "the old key can't sign under the current kid")

	// The current key comes first.
	rec := httptest.NewRecorder()
	route.Handler()(rec, httptest.NewRequest(http.MethodGet, Path, nil))
	var set jwkSet
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &set))
	require.Len(t, set.Keys, 2)
	assert.Equal(t, "key-2", set.Keys[0].Kid)
	assert.Equal(t, "key-1", set.Keys[1].Kid)
}
