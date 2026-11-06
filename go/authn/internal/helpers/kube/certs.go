package kube

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	csrutil "k8s.io/client-go/util/certificate/csr"
)

const (
	certificateWaitTimeout = 5 * time.Minute
	resourceAnnotationKey  = "krateo.user.id"
	customSignerName       = "kubernetes.io/kube-apiserver-client"
)

func NewPrivateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	return key, nil
}

func NewCertificateRequest(key *rsa.PrivateKey, username string, groups []string) ([]byte, error) {
	req := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   username,
			Organization: groups,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	dat, err := x509.CreateCertificateRequest(rand.Reader, &req, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate request: %w", err)
	}

	enc := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: dat})

	return enc, nil
}

// DeleteCertificateSigningRequest deletes a used CSR. CSR names are never
// reused (see NewCertificateSigningRequest), so there is nothing to wait for.
func DeleteCertificateSigningRequest(client kubernetes.Interface, name string) error {
	err := client.CertificatesV1().CertificateSigningRequests().
		Delete(context.Background(), name, metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}

// CreateCertificateSigningRequest creates csr and returns the stored object,
// whose Name the apiserver generated (see NewCertificateSigningRequest).
func CreateCertificateSigningRequest(client kubernetes.Interface, csr *certv1.CertificateSigningRequest) (*certv1.CertificateSigningRequest, error) {
	return client.CertificatesV1().CertificateSigningRequests().
		Create(context.Background(), csr, metav1.CreateOptions{})
}

func ApproveCertificateSigningRequest(client kubernetes.Interface, csr *certv1.CertificateSigningRequest) error {
	/*
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return err
		}

		fmt.Println("rest.Config.Username: ", cfg.Username)

		client, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
	*/
	cond := certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         corev1.ConditionTrue,
		Reason:         "CertificateApproved",
		Message:        "Certificate was approved by authn-service",
		LastUpdateTime: metav1.Now(),
	}

	csr.Status.Conditions = append(csr.Status.Conditions, cond)

	ctx := context.Background()
	_, err := client.CertificatesV1().CertificateSigningRequests().
		UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("approving CertificateSigningRequest: %w", err)
	}
	return nil
}

// WaitForCertificate waits for the signer to issue the CSR, and returns the
// certificate. It watches the CSR, so it returns as soon as the certificate
// exists rather than on a poll tick, and a denied or failed CSR ends it at once.
// A certificate issued before the watch starts isn't missed: client-go lists
// the CSR first.
func WaitForCertificate(client kubernetes.Interface, name string, uid types.UID) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), certificateWaitTimeout)
	defer cancel()

	crt, err := csrutil.WaitForCertificate(ctx, client, name, uid)
	if err != nil {
		return nil, fmt.Errorf("waiting for CSR certificate to be generated: %w", err)
	}
	return crt, nil
}

// NewCertificateSigningRequest builds a CSR whose name the apiserver
// generates from the username plus a random suffix. Every issuance gets its
// own CSR, so concurrent logins of one user (a normal login and a step-up, or
// two browser tabs) never touch each other's request.
func NewCertificateSigningRequest(csr []byte, dur time.Duration, userID, username string) *certv1.CertificateSigningRequest {
	durationSeconds := int32(dur.Seconds())
	csrObject := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: username + "-",
			Annotations: map[string]string{
				resourceAnnotationKey: userID,
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:           csr,
			SignerName:        customSignerName,
			Usages:            []certv1.KeyUsage{certv1.UsageClientAuth},
			ExpirationSeconds: &durationSeconds,
		},
	}
	return csrObject
}
