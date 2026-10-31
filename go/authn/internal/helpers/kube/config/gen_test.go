package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeSigner makes a fake clientset behave like the apiserver for the CSR
// flow: it generates names from generateName and issues a certificate when a
// CSR is approved.
func fakeSigner(t *testing.T) (*fake.Clientset, *[]string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	cli := fake.NewSimpleClientset()
	var mu sync.Mutex
	var created []string
	var seq atomic.Int64

	cli.PrependReactor("create", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
		csr := a.(k8stesting.CreateAction).GetObject().(*certv1.CertificateSigningRequest)
		if csr.Name == "" {
			csr.Name = fmt.Sprintf("%s%05d", csr.GenerateName, seq.Add(1))
		}
		mu.Lock()
		created = append(created, csr.Name)
		mu.Unlock()
		return false, nil, nil // let the tracker store it
	})

	cli.PrependReactor("update", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "approval" {
			return false, nil, nil
		}
		csr := a.(k8stesting.UpdateAction).GetObject().(*certv1.CertificateSigningRequest).DeepCopy()
		block, _ := pem.Decode(csr.Spec.Request)
		req, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return true, nil, err
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(seq.Add(1)), Subject: req.Subject,
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Duration(*csr.Spec.ExpirationSeconds) * time.Second),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, req.PublicKey, caKey)
		if err != nil {
			return true, nil, err
		}
		csr.Status.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		gvr := certv1.SchemeGroupVersion.WithResource("certificatesigningrequests")
		return true, csr, cli.Tracker().Update(gvr, csr, "")
	})

	return cli, &created
}

// Two issuances for the same user at once, such as a normal login and a
// step-up, each get their own CSR and certificate. Neither deletes the
// other's request, and both CSRs are cleaned up afterwards.
func TestConcurrentIssuanceUsesDistinctCSRs(t *testing.T) {
	cli, created := fakeSigner(t)

	type result struct {
		leaf *x509.Certificate
		err  error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i, groups := range [][]string{{"devs"}, {"devs", "krateo:loa:2"}} {
		wg.Add(1)
		go func(i int, groups []string) {
			defer wg.Done()
			_, _, leaf, err := generateClientCertAndKey(cli, zerolog.Nop(), generateClientCertAndKeyOpts{
				duration: 15 * time.Minute, userID: "1", username: "alice", groups: groups,
			})
			results[i] = result{leaf, err}
		}(i, groups)
	}
	wg.Wait()

	for i, r := range results {
		require.NoError(t, r.err, "issuance %d", i)
		assert.Equal(t, "alice", r.leaf.Subject.CommonName)
	}
	assert.Equal(t, []string{"devs"}, results[0].leaf.Subject.Organization)
	assert.Equal(t, []string{"devs", "krateo:loa:2"}, results[1].leaf.Subject.Organization)

	require.Len(t, *created, 2)
	assert.NotEqual(t, (*created)[0], (*created)[1], "each issuance has its own CSR")
	for _, name := range *created {
		assert.Regexp(t, `^alice-\d{5}$`, name)
	}

	left, err := cli.CertificatesV1().CertificateSigningRequests().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, left.Items, "used CSRs are deleted")
}
