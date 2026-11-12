package identitybackfill

import (
	"context"
	"errors"
	"net/http"
	"testing"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// sentinelLookup knows one basic User and one mapping, both named after
// logtest.User; failing makes every lookup fail with an error naming it. UIDs
// are opaque, as the apiserver's are.
type sentinelLookup struct {
	kind    string // "basic" or "serviceaccount"
	mapping bool
	failing bool
}

func (l sentinelLookup) ServiceAccountMapping(_ context.Context, u string) (*sav1alpha1.ServiceAccount, error) {
	if l.failing {
		return nil, errors.New(`serviceaccounts "` + u + `" is unreadable`)
	}
	if l.kind != "serviceaccount" || !l.mapping {
		return nil, nil
	}
	return &sav1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: u, Namespace: ns, UID: "0b1f6c1e"}}, nil
}

func (l sentinelLookup) BasicUserExists(context.Context, string) (bool, error) {
	return l.kind == "basic", nil
}

// The backfill names a Secret by its UID, never by its name, which is its
// user's: whether it stamps, owns, skips, leaves an orphan or is refused
// (Diego, 2026-11-12).
func TestBackfillLogsNoIdentity(t *testing.T) {
	name := logtest.User + "-clientconfig"
	sentinelSecret := func(t *testing.T, annotations map[string]string, certData string) corev1.Secret {
		s := clientConfig(t, name, certData, annotations)
		s.UID = types.UID("8d1c2b7a")
		return s
	}
	good := cert(t, logtest.User, []string{logtest.Marker + "-group"})
	sa := map[string]string{storage.StrategyAnnotation: "serviceaccount", storage.GroupsAnnotation: logtest.Marker + "-group"}
	for _, tc := range []struct {
		name   string
		secret func(t *testing.T) corev1.Secret
		lookup sentinelLookup
		refuse int
		msg    string
	}{
		{name: "stamped", secret: func(t *testing.T) corev1.Secret { return sentinelSecret(t, nil, good) },
			lookup: sentinelLookup{kind: "basic"}, msg: "identity annotations backfilled"},
		{name: "owner backfilled", secret: func(t *testing.T) corev1.Secret { return sentinelSecret(t, sa, good) },
			lookup: sentinelLookup{kind: "serviceaccount", mapping: true}, msg: "clientconfig owner backfilled"},
		{name: "orphan", secret: func(t *testing.T) corev1.Secret { return sentinelSecret(t, sa, good) },
			lookup: sentinelLookup{kind: "serviceaccount"}, msg: "has no ServiceAccount mapping"},
		{name: "the lookup fails", secret: func(t *testing.T) corev1.Secret { return sentinelSecret(t, nil, good) },
			lookup: sentinelLookup{failing: true}, msg: "identity annotations not backfilled"},
		{name: "the certificate is unreadable", secret: func(t *testing.T) corev1.Secret { return sentinelSecret(t, nil, "garbage") },
			lookup: sentinelLookup{kind: "basic"}, msg: "identity annotations not backfilled"},
		{name: "the write is refused", secret: func(t *testing.T) corev1.Secret { return sentinelSecret(t, nil, good) },
			lookup: sentinelLookup{kind: "basic"}, refuse: http.StatusConflict, msg: "identity annotations not backfilled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPIServer(t, []corev1.Secret{tc.secret(t)})
			if tc.refuse != 0 {
				api.refuse = map[string]int{name: tc.refuse}
			}
			logs, l := logtest.Capture()
			_, err := Run(context.Background(), Options{
				RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
				MappingNamespace: ns, Lookup: tc.lookup, Log: l,
			})
			require.NoError(t, err)
			require.Contains(t, logs.String(), tc.msg)
			logtest.NoIdentity(t, logs)
		})
	}
}
