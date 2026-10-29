package kube

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// A signer is free to grant less than the requested `spec.expirationSeconds`:
// the granted lifetime is min(requested, --cluster-signing-duration, signer CA
// remaining life). OpenShift pins the signing duration to 720h and rotates the
// CSR signer CA every 30 days, so a certificate requested for a year can come
// back valid for a day. Nothing downstream may assume the request held — read
// the window off the issued certificate instead.

// ParseCertificatePEM returns the leaf certificate of a PEM-encoded chain
// (the first CERTIFICATE block, which is what a CSR's status.certificate
// carries first).
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}

	return nil, fmt.Errorf("no CERTIFICATE block in PEM data")
}

// ParseCertificateBase64 returns the leaf certificate of a base64-encoded PEM
// chain — the `client-certificate-data` encoding used in kubeconfigs and in the
// `<name>-clientconfig` Secrets.
func ParseCertificateBase64(in string) (*x509.Certificate, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in))
	if err != nil {
		return nil, fmt.Errorf("decoding base64 certificate: %w", err)
	}

	return ParseCertificatePEM(raw)
}

// Lifetime is the granted validity window of a certificate.
func Lifetime(crt *x509.Certificate) time.Duration {
	return crt.NotAfter.Sub(crt.NotBefore)
}

// shortfallRatio is the fraction of the requested duration below which a
// granted lifetime counts as materially short.
const shortfallRatio = 0.9

// MateriallyShorter reports whether the signer granted noticeably less than was
// requested — the symptom of a capped signing duration or of a signer CA whose
// own remaining life is now the binding constraint.
func MateriallyShorter(granted, requested time.Duration) bool {
	if requested <= 0 {
		return false
	}

	return granted < time.Duration(float64(requested)*shortfallRatio)
}
