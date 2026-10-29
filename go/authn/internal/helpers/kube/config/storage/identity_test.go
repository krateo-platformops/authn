package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The groups come from the certificate's O=, newline-separated, so a group
// name containing a comma survives intact.
func TestIdentityAnnotations(t *testing.T) {
	groups := []string{"admins", "Sales, EMEA", "krateo:services"}

	got, err := IdentityAnnotations(StrategyOIDC, identityCert(t, "alice", groups))
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		StrategyAnnotation: "oidc",
		GroupsAnnotation:   "admins\nSales, EMEA\nkrateo:services",
	}, got)
	assert.Equal(t, groups, SplitGroups(got[GroupsAnnotation]))
}

func TestIdentityAnnotationsNoGroups(t *testing.T) {
	got, err := IdentityAnnotations(StrategyBasic, identityCert(t, "bob", nil))
	require.NoError(t, err)

	assert.Equal(t, "", got[GroupsAnnotation])
	assert.Equal(t, []string{}, SplitGroups(got[GroupsAnnotation]))
}

// The annotations are a contract policy decides from, so unlike the validity
// window they are never written from a guess.
func TestIdentityAnnotationsRefuse(t *testing.T) {
	_, err := IdentityAnnotations("", identityCert(t, "alice", nil))
	assert.Error(t, err, "empty strategy")

	_, err = IdentityAnnotations(StrategyBasic, "not a certificate")
	assert.Error(t, err, "unreadable certificate")

	_, err = IdentityAnnotations(StrategyBasic, identityCert(t, "alice", []string{"ok", "two\nlines"}))
	assert.Error(t, err, "a newline in a group cannot be encoded")
}

func TestValidateGroups(t *testing.T) {
	assert.NoError(t, ValidateGroups(nil))
	assert.NoError(t, ValidateGroups([]string{"a", "b, c", "cn=x,ou=y"}))
	assert.Error(t, ValidateGroups([]string{"a", "b\nc"}))
}

// identityCert mints a self-signed client certificate for cn with groups as
// its O=, encoded the way a clientconfig Secret stores it (base64 of PEM).
func identityCert(t *testing.T, cn string, groups []string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: groups},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
