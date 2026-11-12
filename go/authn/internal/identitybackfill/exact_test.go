package identitybackfill

import (
	"context"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

var exactNaming = storage.Naming{Exact: true}

// principalLookup knows mappings by name, each with its declared principal.
type principalLookup struct {
	mappings map[string]string // name -> spec.principal
	basic    map[string]bool
}

func (p principalLookup) ServiceAccountMapping(_ context.Context, u string) (*sav1alpha1.ServiceAccount, error) {
	declared, ok := p.mappings[u]
	if !ok {
		return nil, nil
	}
	return &sav1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: u, Namespace: ns, UID: types.UID("uid-" + u)},
		Spec: sav1alpha1.ServiceAccountSpec{Principal: declared}}, nil
}

func (p principalLookup) BasicUserExists(_ context.Context, u string) (bool, error) {
	return p.basic[u], nil
}

func withLabels(s corev1.Secret, labels map[string]string) corev1.Secret {
	s.Labels = labels
	return s
}

// With exact naming the backfill stamps the absent identity keys, from the
// certificate's CN, never the Secret's name (john.doe's legacy Secret is
// johndoe-clientconfig, and gets john.doe's keys). A key present with another
// value is left as found, logged and audited. Unparseable and non-clientconfig
// Secrets are untouched; nothing is deleted.
func TestRunWithExactNaming(t *testing.T) {
	oidc := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: "devs"}
	items := []corev1.Secret{
		// X/Y: john.doe's legacy Secret, under johndoe's name.
		clientConfig(t, "johndoe-clientconfig", cert(t, "john.doe", []string{"devs"}), oidc),
		clientConfig(t, "alice-clientconfig", cert(t, "alice", []string{"devs"}), oidc),
		clientConfig(t, "authn-clientconfig", cert(t, "authn", []string{"authn"}), nil),
		clientConfig(t, "agent-x-clientconfig", cert(t, "agent-x", []string{"tenants"}), nil),
		clientConfig(t, "svc-y-clientconfig", cert(t, "svc-y", nil), nil),
		clientConfig(t, "gone-clientconfig", cert(t, "gone", nil), map[string]string{storage.StrategyAnnotation: "serviceaccount", storage.GroupsAnnotation: ""}),
		clientConfig(t, "who-clientconfig", cert(t, "who", nil), nil), // strategy unknown
		// Already complete: not written.
		withLabels(clientConfig(t, "done-clientconfig", cert(t, "done", nil),
			map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: "", storage.UsernameAnnotation: "done"}),
			map[string]string{storage.PrincipalLabel: "human", storage.UsernameLabelLabel: "done"}),
		// A conflicting value: left as found, the absent key stamped.
		withLabels(clientConfig(t, "carol-clientconfig", cert(t, "carol", nil),
			map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: "", storage.UsernameAnnotation: "not-carol"}),
			map[string]string{storage.PrincipalLabel: "service", "unrelated": "keep"}),
		// Unparseable: skipped (acme and globex on demo).
		clientConfig(t, "acme-clientconfig", "garbage", oidc),
		// Not a clientconfig.
		{ObjectMeta: metav1.ObjectMeta{Name: "authn-jwt-signing-key", Namespace: ns}},
	}
	api := newFakeAPIServer(t, items)
	ctl, records := auditlogtest.NewController(t, "system:serviceaccount:"+ns+":authn")
	res, err := Run(context.Background(), Options{
		RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
		Lookup: principalLookup{mappings: map[string]string{"agent-x": "agent", "svc-y": ""}},
		Log:    zerolog.Nop(), Audit: ctl, Naming: exactNaming,
	})
	require.NoError(t, err)
	assert.Equal(t, Result{Scanned: 10, Stamped: 8, Skipped: 1, Inconsistent: 1}, res)

	for name, want := range map[string]struct {
		username string
		labels   map[string]string
	}{
		"johndoe-clientconfig": {"john.doe", map[string]string{storage.PrincipalLabel: "human", storage.UsernameLabelLabel: "john-doe--30f69670bba2"}},
		"alice-clientconfig":   {"alice", map[string]string{storage.PrincipalLabel: "human", storage.UsernameLabelLabel: "alice"}},
		"authn-clientconfig":   {"authn", map[string]string{storage.PrincipalLabel: "service", storage.UsernameLabelLabel: "authn"}},
		"agent-x-clientconfig": {"agent-x", map[string]string{storage.PrincipalLabel: "agent", storage.UsernameLabelLabel: "agent-x"}},
		"svc-y-clientconfig":   {"svc-y", map[string]string{storage.PrincipalLabel: "service", storage.UsernameLabelLabel: "svc-y"}},
		// No principal is guessed: the mapping is gone, or the strategy unknown.
		"gone-clientconfig": {"gone", map[string]string{storage.UsernameLabelLabel: "gone"}},
		"who-clientconfig":  {"who", map[string]string{storage.UsernameLabelLabel: "who"}},
	} {
		got, ok := api.updates[name]
		require.True(t, ok, "%s must be stamped", name)
		assert.Equal(t, want.username, got[storage.UsernameAnnotation], "%s: the CN", name)
		assert.Equal(t, "keep", got["unrelated"], "%s: other annotations kept", name)
		assert.Equal(t, want.labels, api.labels[name], name)
	}

	// carol: the conflicting annotation and label are kept, the absent label stamped.
	assert.Equal(t, "not-carol", api.updates["carol-clientconfig"][storage.UsernameAnnotation])
	assert.Equal(t, map[string]string{storage.PrincipalLabel: "service", "unrelated": "keep", storage.UsernameLabelLabel: "carol"},
		api.labels["carol-clientconfig"])

	for _, name := range []string{"done-clientconfig", "acme-clientconfig", "authn-jwt-signing-key"} {
		assert.NotContains(t, api.updates, name, "%s must not be written", name)
	}

	// One backfilled record per write, each conformant. A key left as found
	// is logged only: its record waits for audit's kept_existing_value.
	backfilled := 0
	for _, r := range records.Records() {
		audittest.AssertConformant(t, audit.WriterController, r)
		assert.Equal(t, "authn.identity.backfilled", auditlogtest.String(r, "krateo.action"))
		assert.Equal(t, "success", auditlogtest.String(r, "krateo.audit.outcome"))
		backfilled++
	}
	assert.Equal(t, 8, backfilled)
}

// Flag off, the backfill stamps what it always has: no username annotation,
// no labels.
func TestRunWithLegacyNamingStampsNoIdentityKeys(t *testing.T) {
	api := newFakeAPIServer(t, []corev1.Secret{clientConfig(t, "johndoe-clientconfig", cert(t, "john.doe", nil), nil)})
	res, err := Run(context.Background(), Options{
		RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
		Lookup: principalLookup{basic: map[string]bool{"john.doe": true}}, Log: zerolog.Nop(),
	})
	require.NoError(t, err)
	assert.Equal(t, Result{Scanned: 1, Stamped: 1}, res)
	assert.NotContains(t, api.updates["johndoe-clientconfig"], storage.UsernameAnnotation)
	assert.Nil(t, api.labels["johndoe-clientconfig"])
}

// The X/Y pair at the backfill: johndoe's own Secret and john.doe's legacy one
// share nothing but the name shape; each gets the keys of its own CN, and a
// Secret whose username annotation names the other is left as found.
func TestRunExactXY(t *testing.T) {
	oidc := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: ""}
	mislabelled := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: "", storage.UsernameAnnotation: "johndoe"}
	for _, tc := range []struct {
		name     string
		secret   corev1.Secret
		username string
		label    string
		odd      bool
	}{
		{"johndoe's", clientConfig(t, "johndoe-clientconfig", cert(t, "johndoe", nil), oidc), "johndoe", "johndoe", false},
		{"john.doe's legacy", clientConfig(t, "johndoe-clientconfig", cert(t, "john.doe", nil), oidc), "john.doe", "john-doe--30f69670bba2", false},
		{"john.doe's, annotated johndoe", clientConfig(t, "johndoe-clientconfig", cert(t, "john.doe", nil), mislabelled), "johndoe", "john-doe--30f69670bba2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPIServer(t, []corev1.Secret{tc.secret})
			res, err := Run(context.Background(), Options{
				RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
				Lookup: principalLookup{}, Log: zerolog.Nop(), Naming: exactNaming,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.username, api.updates["johndoe-clientconfig"][storage.UsernameAnnotation])
			assert.Equal(t, tc.label, api.labels["johndoe-clientconfig"][storage.UsernameLabelLabel], "the label follows the CN")
			assert.Equal(t, tc.odd, res.Inconsistent == 1)
		})
	}
}

// The exact backfill's lines name no one: a stamp, a conflict, an unreadable
// certificate.
func TestExactBackfillLogsNoIdentity(t *testing.T) {
	name := logtest.User + "-clientconfig"
	good := cert(t, logtest.User, []string{logtest.Marker + "-group"})
	oidc := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: logtest.Marker + "-group"}
	odd := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: logtest.Marker + "-group",
		storage.UsernameAnnotation: logtest.Marker + "-other"}
	for _, tc := range []struct {
		name   string
		secret corev1.Secret
		msg    string
	}{
		{"stamped", clientConfig(t, name, good, oidc), "identity keys backfilled"},
		{"a conflict", clientConfig(t, name, good, odd), "identity key differs from the certificate"},
		{"unreadable", clientConfig(t, name, "garbage", oidc), "identity keys not backfilled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.secret.UID = "8d1c2b7a"
			api := newFakeAPIServer(t, []corev1.Secret{tc.secret})
			logs, l := logtest.Capture()
			_, err := Run(context.Background(), Options{
				RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
				Lookup: principalLookup{}, Log: l, Naming: exactNaming,
			})
			require.NoError(t, err)
			require.Contains(t, logs.String(), tc.msg)
			logtest.NoIdentity(t, logs)
		})
	}
}

// Each key held with another value than the certificate proves is logged on
// its own line, by key name and the Secret's uid, never a value, left as
// found, and recorded nowhere yet (its record waits for audit v0.14.0's
// kept_existing_value). One test per key.
func TestRunLogsEachConflictingKey(t *testing.T) {
	stamped := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: ""}
	for _, tc := range []struct {
		key    string
		ann    map[string]string
		labels map[string]string
	}{
		{storage.UsernameAnnotation, map[string]string{storage.UsernameAnnotation: logtest.Marker + "-other"}, nil},
		{storage.PrincipalLabel, nil, map[string]string{storage.PrincipalLabel: "agent"}},
		{storage.UsernameLabelLabel, nil, map[string]string{storage.UsernameLabelLabel: "zz-other"}},
	} {
		t.Run(tc.key, func(t *testing.T) {
			ann := map[string]string{}
			for k, v := range stamped {
				ann[k] = v
			}
			for k, v := range tc.ann {
				ann[k] = v
			}
			sec := withLabels(clientConfig(t, logtest.User+"-clientconfig", cert(t, logtest.User, nil), ann), tc.labels)
			sec.UID = "8d1c2b7a"
			api := newFakeAPIServer(t, []corev1.Secret{sec})
			ctl, records := auditlogtest.NewController(t, "system:serviceaccount:"+ns+":authn")
			logs, l := logtest.Capture()
			res, err := Run(context.Background(), Options{
				RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
				Lookup: principalLookup{}, Log: l, Audit: ctl, Naming: exactNaming,
			})
			require.NoError(t, err)
			assert.Equal(t, 1, res.Inconsistent)
			lines := 0
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, "identity key differs from the certificate") {
					lines++
					assert.Contains(t, line, `"key":"`+tc.key+`"`)
					assert.Contains(t, line, `"secret.uid":"8d1c2b7a"`)
				}
			}
			assert.Equal(t, 1, lines, "one line for the key")
			logtest.NoIdentity(t, logs)

			name := logtest.User + "-clientconfig"
			if tc.ann != nil {
				assert.Equal(t, tc.ann[tc.key], api.updates[name][tc.key], "left as found")
			} else {
				assert.Equal(t, tc.labels[tc.key], api.labels[name][tc.key], "left as found")
			}
			for _, r := range records.Records() {
				assert.Equal(t, "authn.identity.backfilled", auditlogtest.String(r, "krateo.action"), "no inconsistency record yet")
			}
		})
	}
}

// A certificate that names no one (an empty CN) proves no username: the
// Secret is skipped, never stamped with an empty one (review of #147).
func TestRunSkipsACertificateWithNoCN(t *testing.T) {
	oidc := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: ""}
	api := newFakeAPIServer(t, []corev1.Secret{clientConfig(t, "nobody-clientconfig", cert(t, "", nil), oidc)})
	res, err := Run(context.Background(), Options{
		RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
		Lookup: principalLookup{}, Log: zerolog.Nop(), Naming: exactNaming,
	})
	require.NoError(t, err)
	assert.Equal(t, Result{Scanned: 1, Skipped: 1}, res)
	assert.NotContains(t, api.updates, "nobody-clientconfig")
}
