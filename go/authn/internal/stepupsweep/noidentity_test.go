package stepupsweep

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The sweep names a step-up Secret by its UID, never by its name, which is
// its user's: whether it deletes one, skips one, or fails (Diego, 2026-11-12).
func TestSweepLogsNoIdentity(t *testing.T) {
	name := logtest.User + "-clientconfig-stepup"
	sentinel := func(cert []byte) *corev1.Secret {
		s := secret(name, "krateo-system", cert)
		s.UID = "5e2f9c41" // opaque, as the apiserver's
		return s
	}
	for _, tc := range []struct {
		name    string
		cert    []byte
		failDel bool
		msg     string
	}{
		{name: "deleted", cert: certData(t, now.Add(-time.Hour)), msg: "expired credential deleted"},
		{name: "unreadable", cert: []byte("not a certificate"), msg: "certificate unreadable"},
		{name: "the delete fails", cert: certData(t, now.Add(-time.Hour)), failDel: true, msg: "step-up sweep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewSimpleClientset(sentinel(tc.cert))
			if tc.failDel {
				c.PrependReactor("delete", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(corev1.Resource("secrets"), a.(k8stesting.DeleteAction).GetName(), errors.New("no"))
				})
			}
			logs, l := logtest.Capture()
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Run makes one pass and returns
			Run(ctx, Options{Client: c, Namespaces: []string{"krateo-system"}, Now: func() time.Time { return now }, Log: l})

			require.Contains(t, logs.String(), tc.msg)
			logtest.NoIdentity(t, logs)
		})
	}
}
