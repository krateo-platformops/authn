package config

import (
	"crypto/x509"
	"fmt"
	"time"

	"encoding/base64"
	"encoding/pem"

	"github.com/krateo-platformops/authn/internal/helpers/kube"
	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

type generateClientCertAndKeyOpts struct {
	duration time.Duration
	userID   string
	username string
	groups   []string
}

// generateClientCertAndKey mints a client certificate through the Kubernetes CSR
// API and returns it base64-PEM encoded together with its key and the PARSED
// leaf, whose NotAfter is the only trustworthy expiry: the signer may grant less
// than o.duration (see internal/helpers/kube/certinfo.go).
func generateClientCertAndKey(client kubernetes.Interface, l zerolog.Logger, o generateClientCertAndKeyOpts) (string, string, *x509.Certificate, error) {
	key, err := kube.NewPrivateKey()
	if err != nil {
		return "", "", nil, err
	}

	req, err := kube.NewCertificateRequest(key, o.username, o.groups)
	if err != nil {
		return "", "", nil, err
	}

	// csr object from csr bytes
	csr := kube.NewCertificateSigningRequest(req, o.duration, o.userID, o.username)

	// create kubernetes csr object
	err = kube.CreateCertificateSigningRequests(client, csr)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return "", "", nil, fmt.Errorf("creating CSR kubernetes object: %w", err)
		}

		l.Debug().Str("crs.name", csr.Name).Msg("certificate signing request already exists")

		if err := kube.DeleteCertificateSigningRequest(client, csr.Name); err != nil {
			return "", "", nil, fmt.Errorf("deleting existing CSR kubernetes object: %w", err)
		}
		l.Debug().Str("crs.name", csr.Name).Msg("existing certificate signing request deleted")

		if err := kube.CreateCertificateSigningRequests(client, csr); err != nil {
			return "", "", nil, fmt.Errorf("creating CSR kubernetes object: %w", err)
		}
	}

	l.Debug().Str("crs.name", csr.Name).Msg("created certificate signing request")

	// approve the csr
	err = kube.ApproveCertificateSigningRequest(client, csr)
	if err != nil {
		return "", "", nil, err
	}
	l.Debug().Str("crs.name", csr.Name).Msg("approved certificate signing request")

	// wait for certificate
	l.Debug().Str("crs.name", csr.Name).Msg("waiting for certificate...")
	err = kube.WaitForCertificate(client, csr.Name)
	if err != nil {
		return "", "", nil, err
	}

	crt, err := kube.Certificate(client, csr.Name)
	if err != nil {
		return "", "", nil, err
	}

	leaf, err := kube.ParseCertificatePEM(crt)
	if err != nil {
		return "", "", nil, fmt.Errorf("parsing issued certificate: %w", err)
	}

	granted := kube.Lifetime(leaf)
	l.Debug().
		Str("crs.name", csr.Name).
		Dur("requested", o.duration).
		Dur("granted", granted).
		Time("notAfter", leaf.NotAfter).
		Msg("certificate acquired")

	// A capped signer is invisible unless it is called out: the request
	// succeeds, only shorter. Warn at issue time when the shortfall is material,
	// so the cause is in the log the first time a session dies early.
	if kube.MateriallyShorter(granted, o.duration) {
		l.Warn().
			Str("crs.name", csr.Name).
			Dur("requested", o.duration).
			Dur("granted", granted).
			Time("notAfter", leaf.NotAfter).
			Msg("signer granted a materially shorter certificate than requested")
	}

	crtStr := base64.StdEncoding.EncodeToString(crt)
	keyStr := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	return crtStr, keyStr, leaf, nil
}
