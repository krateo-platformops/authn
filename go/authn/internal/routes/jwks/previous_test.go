package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
	return path
}

func TestParsePreviousKeys(t *testing.T) {
	dir := t.TempDir()
	current, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	old1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	old2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// The retired private key as it sat in its Secret, and a public-only key.
	privPath := writePEM(t, dir, "old1.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(old1))
	pkix, err := x509.MarshalPKIXPublicKey(&old2.PublicKey)
	require.NoError(t, err)
	pubPath := writePEM(t, dir, "old2.pub", "PUBLIC KEY", pkix)
	currentPath := writePEM(t, dir, "current.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(current))
	garbage := filepath.Join(dir, "garbage")
	require.NoError(t, os.WriteFile(garbage, []byte("not a key"), 0o600))

	keys, err := ParsePreviousKeys("", "key-3", &current.PublicKey)
	require.NoError(t, err)
	assert.Empty(t, keys, "no previous keys configured")

	keys, err = ParsePreviousKeys(" key-1="+privPath+" , key-2="+pubPath+",", "key-3", &current.PublicKey)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "key-1", keys[0].KID)
	assert.True(t, keys[0].Pub.Equal(&old1.PublicKey), "only the public half of a private key is kept")
	assert.Equal(t, "key-2", keys[1].KID)
	assert.True(t, keys[1].Pub.Equal(&old2.PublicKey))

	for name, spec := range map[string]string{
		"no separator":       "key-1",
		"empty kid":          "=" + privPath,
		"empty path":         "key-1=",
		"duplicate kid":      "key-1=" + privPath + ",key-1=" + pubPath,
		"current kid":        "key-3=" + privPath,
		"missing file":       "key-1=" + filepath.Join(dir, "nope.pem"),
		"not a key":          "key-1=" + garbage,
		"current key reused": "key-1=" + currentPath,
	} {
		keys, err := ParsePreviousKeys(spec, "key-3", &current.PublicKey)
		assert.Error(t, err, name)
		assert.Nil(t, keys, name)
	}
}
