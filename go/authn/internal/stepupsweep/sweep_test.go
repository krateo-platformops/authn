package stepupsweep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// certData is a client certificate valid until notAfter, stored the way
// storage.Put stores it: base64 of the PEM.
func certData(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "alice", Organization: []string{"devs", "krateo:loa:2"}},
		NotBefore:    notAfter.Add(-15 * time.Minute),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return []byte(base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}

func secret(name, ns string, cert []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(name + "-uid"), ResourceVersion: "1"},
		Data:       map[string][]byte{storage.ClientCertLabel: cert, storage.ClientKeyLabel: []byte("key")},
	}
}

func names(t *testing.T, c *fake.Clientset, ns string) []string {
	t.Helper()
	list, err := c.CoreV1().Secrets(ns).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	var out []string
	for _, s := range list.Items {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

func TestSweepDeletesOnlyExpiredStepUpSecrets(t *testing.T) {
	expired := certData(t, now.Add(-time.Hour))
	c := fake.NewSimpleClientset(
		secret("alice-clientconfig-stepup", "krateo-system", expired),                              // expired: deleted
		secret("bob-clientconfig-stepup", "krateo-system", certData(t, now.Add(10*time.Minute))),   // still valid
		secret("carol-clientconfig-stepup", "krateo-system", certData(t, now.Add(-2*time.Minute))), // expired within the grace
		secret("alice-clientconfig", "krateo-system", expired),                                     // a session credential, even expired
		secret("dave-clientconfig-stepup", "krateo-system", []byte("not a certificate")),           // unreadable
		secret("-clientconfig-stepup", "krateo-system", expired),                                   // not a user's step-up name
		secret("erin-clientconfig-stepup", "other", expired),                                       // a namespace authn doesn't own
		secret("frank-clientconfig-stepup", "authn-store", expired),                                // the storage namespace
	)

	res, err := Sweep(context.Background(), Options{
		Client:     c,
		Namespaces: []string{"krateo-system", "authn-store", "krateo-system", ""},
		Now:        func() time.Time { return now },
		Log:        zerolog.Nop(),
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"-clientconfig-stepup", "alice-clientconfig", "bob-clientconfig-stepup",
		"carol-clientconfig-stepup", "dave-clientconfig-stepup"}, names(t, c, "krateo-system"))
	assert.Empty(t, names(t, c, "authn-store"))
	assert.Equal(t, []string{"erin-clientconfig-stepup"}, names(t, c, "other"))
	assert.Equal(t, Result{Scanned: 5, Deleted: 2, Skipped: 1}, res)
}

// A step-up that rewrote the Secret between the list and the delete keeps its
// new credential: the delete carries the UID and resourceVersion it read.
func TestSweepNeverDeletesARewrittenSecret(t *testing.T) {
	c := fake.NewSimpleClientset(secret("alice-clientconfig-stepup", "krateo-system", certData(t, now.Add(-time.Hour))))
	var got *metav1.Preconditions
	c.PrependReactor("delete", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		got = a.(k8stesting.DeleteActionImpl).DeleteOptions.Preconditions
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, "alice-clientconfig-stepup", nil)
	})

	res, err := Sweep(context.Background(), Options{Client: c, Namespaces: []string{"krateo-system"},
		Now: func() time.Time { return now }, Log: zerolog.Nop()})
	require.NoError(t, err)

	require.NotNil(t, got)
	assert.Equal(t, types.UID("alice-clientconfig-stepup-uid"), *got.UID)
	assert.Equal(t, "1", *got.ResourceVersion)
	assert.Equal(t, Result{Scanned: 1, Skipped: 1}, res)
	assert.Equal(t, []string{"alice-clientconfig-stepup"}, names(t, c, "krateo-system"))
}

func TestRunSweepsAtOnceAndStopsWithItsContext(t *testing.T) {
	c := fake.NewSimpleClientset(secret("alice-clientconfig-stepup", "krateo-system", certData(t, now.Add(-time.Hour))))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, Options{Client: c, Namespaces: []string{"krateo-system"}, Interval: time.Hour,
			Now: func() time.Time { return now }, Log: zerolog.Nop()})
		close(done)
	}()

	require.Eventually(t, func() bool { return len(names(t, c, "krateo-system")) == 0 }, 5*time.Second, 10*time.Millisecond,
		"the first pass runs immediately, not after Interval")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
