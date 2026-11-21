// Package configtest holds test doubles for the kubeconfig generator's
// dependencies, shared by its own tests and its callers'.
package configtest

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

	"github.com/stretchr/testify/require"
	certv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// maxGeneratedNameBase is how much of a generateName the apiserver keeps.
const maxGeneratedNameBase = 58

// FakeSigner makes a fake clientset behave like the apiserver for the CSR
// flow: it generates names from generateName, gives each CSR its own UID,
// honours a metadata.name field selector on list and watch, and issues a
// certificate when a CSR is approved. client-go's WaitForCertificate relies on
// the field selector and the UID to see only its own CSR: the bare fake
// ignores the selector and leaves UIDs empty, so two concurrent issuances could
// each receive the other's certificate.
func FakeSigner(t testing.TB) (*fake.Clientset, *[]string) {
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
			// As the apiserver does: at most 58 bytes of generateName, then
			// a 5-character suffix (k8s.io/apiserver/pkg/storage/names).
			base := csr.GenerateName
			if len(base) > maxGeneratedNameBase {
				base = base[:maxGeneratedNameBase]
			}
			csr.Name = fmt.Sprintf("%s%05d", base, seq.Add(1))
		}
		if csr.UID == "" {
			csr.UID = types.UID(fmt.Sprintf("csr-uid-%d", seq.Add(1)))
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

	gvr := certv1.SchemeGroupVersion.WithResource("certificatesigningrequests")
	nameMatches := func(sel fields.Selector, obj runtime.Object) bool {
		csr, ok := obj.(*certv1.CertificateSigningRequest)
		return ok && (sel == nil || sel.Matches(fields.Set{"metadata.name": csr.Name}))
	}
	cli.PrependReactor("list", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sel := a.(k8stesting.ListAction).GetListRestrictions().Fields
		obj, err := cli.Tracker().List(gvr, certv1.SchemeGroupVersion.WithKind("CertificateSigningRequest"), "")
		if err != nil {
			return true, nil, err
		}
		list := obj.(*certv1.CertificateSigningRequestList)
		kept := list.Items[:0]
		for i := range list.Items {
			if nameMatches(sel, &list.Items[i]) {
				kept = append(kept, list.Items[i])
			}
		}
		list.Items = kept
		return true, list, nil
	})
	cli.PrependWatchReactor("certificatesigningrequests", func(a k8stesting.Action) (bool, watch.Interface, error) {
		sel := a.(k8stesting.WatchAction).GetWatchRestrictions().Fields
		w, err := cli.Tracker().Watch(gvr, "")
		if err != nil {
			return true, nil, err
		}
		return true, watch.Filter(w, func(e watch.Event) (watch.Event, bool) {
			return e, nameMatches(sel, e.Object)
		}), nil
	})

	return cli, &created
}
