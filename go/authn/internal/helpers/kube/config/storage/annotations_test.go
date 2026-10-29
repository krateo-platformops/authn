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

func TestCertValidityAnnotations(t *testing.T) {
	notBefore := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	// A one-year request that the signer capped at OpenShift's 720h: the
	// annotations must report what was granted, never what was asked for.
	notAfter := notBefore.Add(time.Hour * 720)

	got := CertValidityAnnotations(certificate(t, notBefore, notAfter))

	assert.Equal(t, map[string]string{
		NotBeforeAnnotation: "2026-09-04T10:00:00Z",
		NotAfterAnnotation:  "2026-10-04T10:00:00Z",
	}, got)
}

// An unreadable certificate must not block storing the credential: the
// annotations are observability, and Put stamps whatever comes back.
func TestCertValidityAnnotationsTolerateGarbage(t *testing.T) {
	assert.Nil(t, CertValidityAnnotations(""))
	assert.Nil(t, CertValidityAnnotations("not base64 at all!!"))
	assert.Nil(t, CertValidityAnnotations(base64.StdEncoding.EncodeToString([]byte("not a pem block"))))
}

// certificate mints a self-signed certificate with the given validity window,
// encoded the way a clientconfig Secret stores it (base64 of PEM).
func certificate(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "authn"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
