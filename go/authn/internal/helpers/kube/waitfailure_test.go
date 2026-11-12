package kube

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	certv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const sentinelCSR = "zz-sentinel-user-00001"

var csrs = certv1.Resource("certificatesigningrequests")

// A wait that failed for its own reason, a Forbidden watch for one, says so
// beside the CSR's state, by the error's class, never by its text.
func TestWaitFailureNamesTheWaitErrorsClass(t *testing.T) {
	cli := fake.NewSimpleClientset(&certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: sentinelCSR, UID: "u1"}})
	watchErr := apierrors.NewForbidden(csrs, sentinelCSR, errors.New("cannot watch"))
	got := waitFailure(context.Background(), cli, sentinelCSR, "u1", watchErr)
	assert.Equal(t, "the wait ended without a certificate (the wait: Forbidden (403))", got)

	// client-go's own errors have no class: the CSR's state alone.
	got = waitFailure(context.Background(), cli, sentinelCSR, "u1", errors.New(`csr "`+sentinelCSR+`" changed UIDs`))
	assert.Equal(t, "the wait ended without a certificate", got)

	expired, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Equal(t, "timed out", waitFailure(expired, cli, sentinelCSR, "u1", context.Canceled))
}

// When the wait fails and the CSR can't be read either, neither error's text
// is repeated: both name the CSR.
func TestWaitFailureWhenTheCSRIsUnreadable(t *testing.T) {
	cli := fake.NewSimpleClientset()
	cli.PrependReactor("get", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(csrs, a.(k8stesting.GetAction).GetName(), errors.New("cannot get"))
	})
	got := waitFailure(context.Background(), cli, sentinelCSR, "u1",
		apierrors.NewForbidden(csrs, sentinelCSR, errors.New("cannot watch")))
	assert.Equal(t, "the wait failed, and the CSR's state can't be read (reading it: Forbidden (403)) (the wait: Forbidden (403))", got)
	assert.NotContains(t, got, "zz-sentinel")
}
