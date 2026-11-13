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
	sdklog "go.opentelemetry.io/otel/sdk/log"
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

	// One backfilled record per write, and one kept_existing_value record per
	// key left as found (carol's username annotation and principal label),
	// each conformant.
	backfilled := 0
	var kept []string
	for _, r := range records.Records() {
		audittest.AssertConformant(t, audit.WriterController, r)
		switch auditlogtest.String(r, "krateo.action") {
		case "authn.identity.backfilled":
			assert.Equal(t, "success", auditlogtest.String(r, "krateo.audit.outcome"))
			backfilled++
		case "authn.identity.inconsistent":
			assert.Equal(t, "carol-clientconfig", auditlogtest.String(r, audit.KeyObjectName))
			kept = append(kept, auditlogtest.String(r, audit.KeyAuthorizationKey))
		default:
			t.Errorf("unexpected record %q", auditlogtest.String(r, "krateo.action"))
		}
	}
	assert.Equal(t, 8, backfilled)
	assert.ElementsMatch(t, []string{"annotation:" + storage.UsernameAnnotation, "label:" + storage.PrincipalLabel}, kept)
}

// Flag off, the backfill compares no identity key: a Secret holding a
// username annotation and labels that differ from its certificate is left as
// it is, logged nowhere and recorded nowhere as inconsistent. The only record
// is the ordinary backfill of what it always stamps.
func TestRunWithLegacyNamingRecordsNoKeptKey(t *testing.T) {
	ann := map[string]string{storage.UsernameAnnotation: "not-carol"}
	sec := withLabels(clientConfig(t, "carol-clientconfig", cert(t, "carol", nil), ann),
		map[string]string{storage.PrincipalLabel: "service", storage.UsernameLabelLabel: "not-carol"})
	api := newFakeAPIServer(t, []corev1.Secret{sec})
	ctl, records := auditlogtest.NewController(t, "system:serviceaccount:"+ns+":authn")
	logs, l := logtest.Capture()
	res, err := Run(context.Background(), Options{
		RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
		Lookup: principalLookup{basic: map[string]bool{"carol": true}}, Log: l, Audit: ctl,
	})
	require.NoError(t, err)
	assert.Zero(t, res.Inconsistent)
	assert.NotContains(t, logs.String(), "identity key differs from the certificate")
	for _, r := range records.Records() {
		assert.NotEqual(t, "authn.identity.inconsistent", auditlogtest.String(r, "krateo.action"), "no key is compared with the flag off")
	}
	assert.Equal(t, "not-carol", api.updates["carol-clientconfig"][storage.UsernameAnnotation], "left as it is")
	assert.Equal(t, "not-carol", api.labels["carol-clientconfig"][storage.UsernameLabelLabel], "left as it is")
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
// its own line, by its kind, its name and the Secret's uid, never a value,
// left as found, and recorded once as a denied update with
// kept_existing_value and the key as <kind>:<key>. One test per key.
func TestRunLogsEachConflictingKey(t *testing.T) {
	stamped := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: ""}
	for _, tc := range []struct {
		kind   string
		key    string
		ann    map[string]string
		labels map[string]string
	}{
		{audit.MetadataKindAnnotation, storage.UsernameAnnotation, map[string]string{storage.UsernameAnnotation: logtest.Marker + "-other"}, nil},
		{audit.MetadataKindLabel, storage.PrincipalLabel, nil, map[string]string{storage.PrincipalLabel: "agent"}},
		{audit.MetadataKindLabel, storage.UsernameLabelLabel, nil, map[string]string{storage.UsernameLabelLabel: "zz-other"}},
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
					assert.Contains(t, line, `"kind":"`+tc.kind+`"`)
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
			var kept []sdklog.Record
			for _, r := range records.Records() {
				if auditlogtest.String(r, "krateo.action") == "authn.identity.inconsistent" {
					kept = append(kept, r)
				}
			}
			require.Len(t, kept, 1, "one record for the key")
			r := kept[0]
			audittest.AssertConformant(t, audit.WriterController, r)
			audittest.AssertRequiredKeysDetected(t, audit.WriterController, r)
			assert.Equal(t, "denied", auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, audit.DenialReasonKeptExistingValue, auditlogtest.String(r, "krateo.audit.denial_reason"))
			assert.Equal(t, tc.kind+":"+tc.key, auditlogtest.String(r, audit.KeyAuthorizationKey))
			assert.Equal(t, "8d1c2b7a", auditlogtest.String(r, audit.KeyObjectUID))
			// The record names the Secret (an audit record may), never the
			// value it kept.
			value := tc.ann[tc.key] + tc.labels[tc.key]
			for _, kv := range audittest.Attributes(r) {
				assert.NotEqual(t, value, kv.Value.Emit(), "%s: never the kept value", kv.Key)
				assert.NotContains(t, kv.Value.Emit(), "-other", "%s: never the kept value", kv.Key)
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

// Three keys in conflict on one Secret are three lines and three records, one
// per key.
func TestRunLogsEveryConflictingKeyOfASecret(t *testing.T) {
	ann := map[string]string{storage.StrategyAnnotation: "oidc", storage.GroupsAnnotation: "", storage.UsernameAnnotation: "other"}
	sec := withLabels(clientConfig(t, "alice-clientconfig", cert(t, "alice", nil), ann),
		map[string]string{storage.PrincipalLabel: "agent", storage.UsernameLabelLabel: "other"})
	api := newFakeAPIServer(t, []corev1.Secret{sec})
	logs, l := logtest.Capture()
	ctl, records := auditlogtest.NewController(t, "system:serviceaccount:"+ns+":authn")
	res, err := Run(context.Background(), Options{
		RestConfig: &rest.Config{Host: api.URL}, Namespaces: []string{ns}, SelfUsername: "authn",
		Lookup: principalLookup{}, Log: l, Audit: ctl, Naming: exactNaming,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Inconsistent, "one Secret")
	var kept []string
	for _, r := range records.Records() {
		audittest.AssertConformant(t, audit.WriterController, r)
		assert.Equal(t, "authn.identity.inconsistent", auditlogtest.String(r, "krateo.action"), "nothing absent, nothing written")
		kept = append(kept, auditlogtest.String(r, audit.KeyAuthorizationKey))
	}
	assert.ElementsMatch(t, []string{"annotation:" + storage.UsernameAnnotation,
		"label:" + storage.PrincipalLabel, "label:" + storage.UsernameLabelLabel}, kept)
	var keys []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "identity key differs from the certificate") {
			for _, k := range []string{storage.UsernameAnnotation, storage.PrincipalLabel, storage.UsernameLabelLabel} {
				if strings.Contains(line, `"key":"`+k+`"`) {
					keys = append(keys, k)
				}
			}
		}
	}
	assert.ElementsMatch(t, []string{storage.UsernameAnnotation, storage.PrincipalLabel, storage.UsernameLabelLabel}, keys)
	assert.NotContains(t, api.updates, "alice-clientconfig", "nothing absent, nothing written")
}

// Every identity key the backfill compares is declared by audit under the
// kind it is compared as, so each kept key's record names it.
func TestEveryExactIdentityKeyIsDeclaredUnderItsKind(t *testing.T) {
	for _, strategy := range []storage.Strategy{storage.StrategyOIDC, storage.StrategyServiceAccount, storage.StrategyUnknown} {
		ann, labels := storage.ExactIdentity(strategy, "agent", "alice")
		for kind, keys := range map[string]map[string]string{audit.MetadataKindAnnotation: ann, audit.MetadataKindLabel: labels} {
			for k := range keys {
				_, ok := audit.AuthorizationKeyValue(kind, k)
				assert.True(t, ok, "%s %s is declared by audit", kind, k)
			}
		}
	}
}
