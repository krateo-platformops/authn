package kube

import (
	"context"
	"strings"
	"testing"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

const testCSRName = "alice-00001"

var testCSRUID = types.UID("c5a1")

func pendingCSR() *certv1.CertificateSigningRequest {
	return &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: testCSRName, UID: testCSRUID},
		Status: certv1.CertificateSigningRequestStatus{
			Conditions: []certv1.CertificateSigningRequestCondition{
				{Type: certv1.CertificateApproved, Status: "True"},
			},
		},
	}
}

// A login waits on this, so it must end when the certificate exists. It used
// to sit out a fixed 3s before its first look.
func TestWaitForCertificateReturnsWhenIssued(t *testing.T) {
	cli := fake.NewClientset(pendingCSR())

	go func() {
		time.Sleep(100 * time.Millisecond)
		issued := pendingCSR()
		issued.Status.Certificate = []byte("cert")
		if _, err := cli.CertificatesV1().CertificateSigningRequests().
			UpdateStatus(context.Background(), issued, metav1.UpdateOptions{}); err != nil {
			t.Errorf("issuing: %v", err)
		}
	}()

	start := time.Now()
	crt, err := WaitForCertificate(cli, testCSRName, testCSRUID)
	if err != nil {
		t.Fatalf("WaitForCertificate: %v", err)
	}
	if string(crt) != "cert" {
		t.Fatalf("certificate = %q, want %q", crt, "cert")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("took %s after the certificate was issued at 100ms", took)
	}
}

// The signer can win the race with the wait.
func TestWaitForCertificateAlreadyIssued(t *testing.T) {
	issued := pendingCSR()
	issued.Status.Certificate = []byte("cert")

	crt, err := WaitForCertificate(fake.NewClientset(issued), testCSRName, testCSRUID)
	if err != nil {
		t.Fatalf("WaitForCertificate: %v", err)
	}
	if string(crt) != "cert" {
		t.Fatalf("certificate = %q, want %q", crt, "cert")
	}
}

// A CSR that will never be issued ends the wait at once, not at the timeout.
func TestWaitForCertificateRefused(t *testing.T) {
	for _, tc := range []struct {
		cond certv1.RequestConditionType
		want string
	}{
		{certv1.CertificateDenied, "denied"},
		{certv1.CertificateFailed, "failed"},
	} {
		t.Run(string(tc.cond), func(t *testing.T) {
			csr := pendingCSR()
			csr.Status.Conditions = append(csr.Status.Conditions,
				certv1.CertificateSigningRequestCondition{Type: tc.cond, Status: "True", Reason: "Test"})

			_, err := WaitForCertificate(fake.NewClientset(csr), testCSRName, testCSRUID)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one saying %q", err, tc.want)
			}
		})
	}
}
