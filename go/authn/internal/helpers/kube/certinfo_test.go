package kube

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

// issue mints a self-signed certificate with the given validity window, PEM
// encoded the way a CSR's status.certificate carries it.
func issue(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "authn", Organization: []string{"authn"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseCertificate(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	notAfter := notBefore.Add(time.Hour * 720)
	crtPEM := issue(t, notBefore, notAfter)

	t.Run("from PEM", func(t *testing.T) {
		crt, err := ParseCertificatePEM(crtPEM)
		require.NoError(t, err)
		assert.Equal(t, notAfter, crt.NotAfter)
		assert.Equal(t, "authn", crt.Subject.CommonName)
	})

	t.Run("from base64 PEM", func(t *testing.T) {
		crt, err := ParseCertificateBase64(base64.StdEncoding.EncodeToString(crtPEM))
		require.NoError(t, err)
		assert.Equal(t, notAfter, crt.NotAfter)
	})

	// status.certificate may carry the signer's chain after the leaf; the leaf
	// is the one whose expiry bounds the session.
	t.Run("leaf of a chain", func(t *testing.T) {
		intermediate := issue(t, notBefore, notBefore.Add(time.Hour*24*3650))
		crt, err := ParseCertificatePEM(append(append([]byte{}, crtPEM...), intermediate...))
		require.NoError(t, err)
		assert.Equal(t, notAfter, crt.NotAfter)
	})

	t.Run("lifetime", func(t *testing.T) {
		crt, err := ParseCertificatePEM(crtPEM)
		require.NoError(t, err)
		assert.Equal(t, time.Hour*720, Lifetime(crt))
	})
}

func TestParseCertificateRejectsGarbage(t *testing.T) {
	_, err := ParseCertificateBase64("")
	assert.Error(t, err, "an empty value is not a certificate")

	_, err = ParseCertificateBase64("not base64 at all!!")
	assert.Error(t, err)

	_, err = ParseCertificatePEM([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"))
	assert.Error(t, err, "a CSR is not a certificate")
}

func TestMateriallyShorter(t *testing.T) {
	year := time.Hour * 8760

	// OpenShift's 720h cap against a one-year request: the whole point of the
	// warning.
	assert.True(t, MateriallyShorter(time.Hour*720, year))
	// A signer CA with a day left.
	assert.True(t, MateriallyShorter(time.Hour*24, year))
	// Granted in full, and the few seconds a signer shaves off it.
	assert.False(t, MateriallyShorter(year, year))
	assert.False(t, MateriallyShorter(year-time.Minute, year))
	// The 24h login default, which sits far below every cap.
	assert.False(t, MateriallyShorter(time.Hour*24, time.Hour*24))
	// No request to compare against.
	assert.False(t, MateriallyShorter(time.Hour, 0))
}
