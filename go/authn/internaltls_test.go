package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writePair writes a self-signed certificate for 127.0.0.1 with the given
// serial and its key to dir, as cert-manager's Secret volume holds them, and
// returns the certificate.
func writePair(t *testing.T, dir string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "authn-internal"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// bump moves both files' modification time forward, as the kubelet's swap of
// a Secret volume does, so a rewrite within the same second is still seen.
func bump(t *testing.T, dir string, by time.Duration) {
	t.Helper()
	at := time.Now().Add(by)
	for _, f := range []string{"tls.crt", "tls.key"} {
		require.NoError(t, os.Chtimes(filepath.Join(dir, f), at, at))
	}
}

// Neither file is plain HTTP, as before; one alone, or a pair that doesn't
// load, refuses to start rather than quietly serving the internal port
// without the TLS it was configured for.
func TestInternalTLSConfig(t *testing.T) {
	cfg, err := internalTLSConfig("", "", zerolog.Nop())
	require.NoError(t, err)
	assert.Nil(t, cfg, "no files: plain HTTP")

	dir := t.TempDir()
	writePair(t, dir, 1)
	crt, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")

	_, err = internalTLSConfig(crt, "", zerolog.Nop())
	assert.Error(t, err, "a certificate without its key")
	_, err = internalTLSConfig("", key, zerolog.Nop())
	assert.Error(t, err, "a key without its certificate")
	_, err = internalTLSConfig(crt, filepath.Join(dir, "missing.key"), zerolog.Nop())
	assert.Error(t, err, "a key file that isn't there")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "garbage.crt"), []byte("not a certificate"), 0o600))
	_, err = internalTLSConfig(filepath.Join(dir, "garbage.crt"), key, zerolog.Nop())
	assert.Error(t, err, "a certificate that doesn't parse")

	cfg, err = internalTLSConfig(crt, key, zerolog.Nop())
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.NotNil(t, cfg.GetCertificate)
}

// The internal listener built with TLS, served as main serves it, answers
// HTTPS and refuses plain HTTP: the request never reaches the handler.
func TestInternalListenerServesOnlyTLS(t *testing.T) {
	dir := t.TempDir()
	cert := writePair(t, dir, 1)
	cfg, err := internalTLSConfig(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), zerolog.Nop())
	require.NoError(t, err)

	var reached atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, "checked")
	})
	_, internal, err := newServers(http.NotFoundHandler(), handler, 8082, 8090, cfg)
	require.NoError(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = serveOn(internal, l) }()
	t.Cleanup(func() { _ = internal.Close() })

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	res, err := client.Get("https://" + l.Addr().String() + "/usernames/check")
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	assert.Equal(t, "checked", string(body))
	assert.EqualValues(t, 1, reached.Load())

	plain := &http.Client{Timeout: 5 * time.Second}
	res, err = plain.Get("http://" + l.Addr().String() + "/usernames/check")
	require.NoError(t, err, "the TLS server answers a plain-HTTP request rather than dropping it")
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, strings.ToLower(string(body)), "https")
	assert.EqualValues(t, 1, reached.Load(), "plain HTTP never reaches the handler")
}

// cert-manager renews the Secret and the kubelet swaps the files: the next
// handshake serves the new certificate, with no restart. A pair read
// mid-swap (a certificate whose key hasn't followed yet) keeps the last
// good one in service and is retried.
func TestCertReloaderPicksUpRotation(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, 1)
	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), zerolog.Nop())
	require.NoError(t, err)
	serialOf := func() int64 {
		c, err := r.GetCertificate(nil)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		require.NoError(t, err)
		return leaf.SerialNumber.Int64()
	}
	assert.EqualValues(t, 1, serialOf())
	assert.EqualValues(t, 1, serialOf(), "unchanged files are not reloaded")

	writePair(t, dir, 2)
	bump(t, dir, time.Second)
	assert.EqualValues(t, 2, serialOf(), "the rotated certificate is served")

	// Mid-swap: a new certificate next to the old key.
	keep, err := os.ReadFile(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	writePair(t, dir, 3)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keep, 0o600))
	bump(t, dir, 2*time.Second)
	assert.EqualValues(t, 2, serialOf(), "a pair that doesn't match keeps the last good certificate")

	writePair(t, dir, 4)
	bump(t, dir, 3*time.Second)
	assert.EqualValues(t, 4, serialOf(), "once the swap completes, the new pair is served")
}
