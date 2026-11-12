package storage

import (
	"strings"
	"testing"

	"github.com/krateo-platformops/plumbing/endpoints"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The X/Y pair of authn#140: john.doe's legacy name is johndoe's name.
const (
	userX = "john.doe"
	userY = "johndoe"
)

var (
	legacyNaming = Naming{}
	exactNaming  = Naming{Exact: true}
)

// With legacy naming every name is main's: the username made DNS-1123
// compatible. With exact naming a name is the username itself when it can be
// (plumbing endpoints.ExactSecretName), the legacy one otherwise, and readers
// try exact then legacy.
func TestNamingNamesTheSecrets(t *testing.T) {
	long := strings.Repeat("a", endpoints.MaxExactUsernameLength+1)
	longest := strings.Repeat("a", endpoints.MaxExactUsernameLength)
	for _, tc := range []struct {
		username             string
		legacy, exact        string
		legacyStep, exactStp string
		exactReads           []string
		issuable             bool
	}{
		{userX, "johndoe-clientconfig", "john.doe-clientconfig", "johndoe-clientconfig-stepup", "john.doe-clientconfig-stepup",
			[]string{"john.doe-clientconfig", "johndoe-clientconfig"}, true},
		{userY, "johndoe-clientconfig", "johndoe-clientconfig", "johndoe-clientconfig-stepup", "johndoe-clientconfig-stepup",
			[]string{"johndoe-clientconfig"}, true},
		{"Pinco.Pallo@kubeworld.it", "pincopallokubeworldit-clientconfig", "pincopallokubeworldit-clientconfig",
			"pincopallokubeworldit-clientconfig-stepup", "pincopallokubeworldit-clientconfig-stepup",
			[]string{"pincopallokubeworldit-clientconfig"}, false},
		// The legacy rewrite cuts a name to 63, so a long name's legacy name
		// is another one.
		{longest, ClientConfigSecretName(longest), longest + "-clientconfig", StepUpSecretName(longest), longest + "-clientconfig-stepup",
			[]string{longest + "-clientconfig", strings.Repeat("a", 63) + "-clientconfig"}, true},
		{long, ClientConfigSecretName(long), ClientConfigSecretName(long), StepUpSecretName(long), StepUpSecretName(long),
			[]string{ClientConfigSecretName(long)}, false},
	} {
		t.Run(tc.username[:min(len(tc.username), 20)], func(t *testing.T) {
			assert.Equal(t, tc.legacy, legacyNaming.SessionName(tc.username))
			assert.Equal(t, tc.legacyStep, legacyNaming.StepUpName(tc.username))
			assert.Equal(t, []string{tc.legacy}, legacyNaming.SessionNames(tc.username))
			assert.True(t, legacyNaming.Issuable(tc.username), "legacy naming issues every name")

			assert.Equal(t, tc.exact, exactNaming.SessionName(tc.username))
			assert.Equal(t, tc.exactStp, exactNaming.StepUpName(tc.username))
			assert.Equal(t, tc.exactReads, exactNaming.SessionNames(tc.username))
			assert.Equal(t, tc.exactReads[0], exactNaming.SessionName(tc.username), "the first read is the name authn writes")
			assert.Equal(t, tc.issuable, exactNaming.Issuable(tc.username))
		})
	}
}

// The username-label vectors of acmp's tenant-policy design (§2.5), at the
// frozen bound 56.
func TestUsernameLabelIsBoundedAt56(t *testing.T) {
	require.Equal(t, 56, UsernameLabelMaxLen, "frozen: the tenant policy's namespace is tenant-<label>, at most 63")
	for u, want := range map[string]string{
		userX:  "john-doe--30f69670bba2",
		userY:  "johndoe",
		"a--b": "a--b--90827a2e5636",
	} {
		got, ok := UsernameLabel(u)
		assert.True(t, ok, u)
		assert.Equal(t, want, got, u)
	}
	got, ok := UsernameLabel(strings.Repeat("a", 57))
	assert.True(t, ok)
	assert.Len(t, got, 56)
	assert.Len(t, "tenant-"+got, 63)

	for _, u := range []string{"", "-alice", "Alice"} {
		_, ok := UsernameLabel(u)
		assert.False(t, ok, "%q: no valid label value, so none is stamped", u)
	}
}

// human for a person's sign-in; a mapping's declared kind, never human;
// service for authn; nothing for a strategy that proves no kind.
func TestPrincipalForEachStrategy(t *testing.T) {
	for _, tc := range []struct {
		strategy Strategy
		declared string
		want     string
		ok       bool
	}{
		{StrategyBasic, "", "human", true},
		{StrategyLDAP, "", "human", true},
		{StrategyOAuth, "", "human", true},
		{StrategyOIDC, "", "human", true},
		{StrategyOIDC, "agent", "human", true}, // only a mapping declares its kind
		{StrategyServiceAccount, "", "service", true},
		{StrategyServiceAccount, "agent", "agent", true},
		{StrategyServiceAccount, "controller", "controller", true},
		{StrategyServiceAccount, "service", "service", true},
		{StrategyServiceAccount, "human", "service", true}, // a mapping is never human
		{StrategyServiceAccount, "robot", "service", true},
		{StrategySelf, "", "service", true},
		{StrategyUnknown, "", "", false},
		{"", "", "", false},
	} {
		got, ok := PrincipalFor(tc.strategy, tc.declared)
		assert.Equal(t, tc.want, got, "%s/%s", tc.strategy, tc.declared)
		assert.Equal(t, tc.ok, ok, "%s/%s", tc.strategy, tc.declared)
	}
}

func TestExactIdentity(t *testing.T) {
	ann, labels := ExactIdentity(StrategyOIDC, "", userX)
	assert.Equal(t, map[string]string{"authn.krateo.io/username": userX}, ann)
	assert.Equal(t, map[string]string{"authn.krateo.io/principal": "human", "authn.krateo.io/username-label": "john-doe--30f69670bba2"}, labels)

	_, labels = ExactIdentity(StrategyUnknown, "", userY)
	assert.Equal(t, map[string]string{"authn.krateo.io/username-label": userY}, labels, "no principal is guessed")
}

// Legacy naming judges authorization-bearing content by the annotations, as
// authn always has; exact naming through content.DiffersWith, the username
// annotation and both labels included.
func TestAuthorizationDiffers(t *testing.T) {
	sec := func(ann, labels map[string]string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "x-clientconfig", Annotations: ann, Labels: labels},
			Data: map[string][]byte{ClientCertLabel: []byte("c")}}
	}
	base := sec(map[string]string{StrategyAnnotation: "oidc"}, nil)
	for _, tc := range []struct {
		name          string
		after         *corev1.Secret
		legacy, exact bool
	}{
		{"nothing", sec(map[string]string{StrategyAnnotation: "oidc"}, nil), false, false},
		{"strategy", sec(map[string]string{StrategyAnnotation: "ldap"}, nil), true, true},
		{"the validity window", sec(map[string]string{StrategyAnnotation: "oidc", NotAfterAnnotation: "x"}, nil), false, false},
		{"the username annotation", sec(map[string]string{StrategyAnnotation: "oidc", UsernameAnnotation: "x"}, nil), false, true},
		{"the principal label", sec(map[string]string{StrategyAnnotation: "oidc"}, map[string]string{PrincipalLabel: "human"}), false, true},
		{"the username-label label", sec(map[string]string{StrategyAnnotation: "oidc"}, map[string]string{UsernameLabelLabel: "x"}), false, true},
		{"an unrelated label", sec(map[string]string{StrategyAnnotation: "oidc"}, map[string]string{"x": "y"}), false, false},
	} {
		assert.Equal(t, tc.legacy, legacyNaming.AuthorizationDiffers(base, tc.after), "legacy: %s", tc.name)
		assert.Equal(t, tc.exact, exactNaming.AuthorizationDiffers(base, tc.after), "exact: %s", tc.name)
	}
	keys := ContentKeys()
	assert.Contains(t, keys.Annotations, UsernameAnnotation)
	assert.Contains(t, keys.Annotations, StrategyAnnotation)
	assert.ElementsMatch(t, []string{PrincipalLabel, UsernameLabelLabel}, keys.Labels)
}

// Ownership is endpoints.OwnsSecret with either naming: the username
// annotation, else the certificate's CN.
func TestNamingOwns(t *testing.T) {
	byAnnotation := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{UsernameAnnotation: userY}}}
	byCN := &corev1.Secret{Data: map[string][]byte{ClientCertLabel: []byte(identityCert(t, userY, nil))}}
	for _, sec := range []*corev1.Secret{byAnnotation, byCN} {
		assert.True(t, exactNaming.Owns(sec, userY))
		assert.False(t, exactNaming.Owns(sec, userX), "johndoe's Secret is never john.doe's")
		assert.False(t, legacyNaming.Owns(sec, userX), "ownership is the same with either naming")
	}
	assert.False(t, exactNaming.Owns(&corev1.Secret{}, userY), "no annotation and no certificate: nobody's")
}
