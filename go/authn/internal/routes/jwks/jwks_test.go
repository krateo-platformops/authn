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
