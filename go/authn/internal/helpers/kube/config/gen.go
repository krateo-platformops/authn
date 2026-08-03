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

func generateClientCertAndKey(client kubernetes.Interface, l zerolog.Logger, o generateClientCertAndKeyOpts) (string, string, error) {
	key, err := kube.NewPrivateKey()
	if err != nil {
		return "", "", err
	}

	req, err := kube.NewCertificateRequest(key, o.username, o.groups)
	if err != nil {
		return "", "", err
	}

	// csr object from csr bytes
	csr := kube.NewCertificateSigningRequest(req, o.duration, o.userID, o.username)

	// create kubernetes csr object
	err = kube.CreateCertificateSigningRequests(client, csr)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return "", "", fmt.Errorf("creating CSR kubernetes object: %w", err)
		}

		l.Debug().Str("crs.name", csr.Name).Msg("certificate signing request already exists")

		if err := kube.DeleteCertificateSigningRequest(client, csr.Name); err != nil {
			return "", "", fmt.Errorf("deleting existing CSR kubernetes object: %w", err)
		}
		l.Debug().Str("crs.name", csr.Name).Msg("existing certificate signing request deleted")

		if err := kube.CreateCertificateSigningRequests(client, csr); err != nil {
			return "", "", fmt.Errorf("creating CSR kubernetes object: %w", err)
		}
	}

	l.Debug().Str("crs.name", csr.Name).Msg("created certificate signing request")

	// approve the csr
	err = kube.ApproveCertificateSigningRequest(client, csr)
	if err != nil {
		return "", "", err
	}
	l.Debug().Str("crs.name", csr.Name).Msg("approved certificate signing request")

	// wait for certificate
	l.Debug().Str("crs.name", csr.Name).Msg("waiting for certificate...")
	err = kube.WaitForCertificate(client, csr.Name)
	if err != nil {
		return "", "", err
	}

	crt, err := kube.Certificate(client, csr.Name)
	if err != nil {
		return "", "", err
	}
	l.Debug().Str("crs.name", csr.Name).Msg("certificate acquired")

	crtStr := base64.StdEncoding.EncodeToString(crt)
	keyStr := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	return crtStr, keyStr, nil
}
