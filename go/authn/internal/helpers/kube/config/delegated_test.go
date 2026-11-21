package config

import (
	"errors"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/endpoints"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// readBack is sec as a reader gets it: what was sent as StringData is Data.
func readBack(sec *corev1.Secret) *corev1.Secret {
	out := sec.DeepCopy()
	if out.Data == nil {
		out.Data = map[string][]byte{}
	}
	for k, v := range sec.StringData {
		out.Data[k] = []byte(v)
	}
	out.StringData = nil
	return out
}

func legacyGenerator(t *testing.T, rc *rest.Config) *kubeconfigGenerator {
	t.Helper()
	cli, _ := fakeSigner(t)
	gen := NewGenerator(rc, CAData("ca"), KubernetesURL("https://k8s.example"), CertDuration(time.Hour),
		Log(zerolog.Nop()), Lookup(&namesLookup{})).(*kubeconfigGenerator)
	gen.csrClient = cli
	return gen
}

// authn#167, end to end through the signer and the store: the delegated
// credential is a certificate for exactly the token's username and groups,
// in the Secret named for the person and the actor, which the reader's check
// (endpoints.CheckDelegatedCredential) finds held. Its lifetime is the
// token's, at least the CSR API's minimum, and the session Secret is never
// written.
func TestGenerateDelegated(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	for _, tc := range []struct {
		name string
		gen  func(*testing.T, *rest.Config) *kubeconfigGenerator
	}{
		{"legacy naming", legacyGenerator},
		{"exact naming", func(t *testing.T, rc *rest.Config) *kubeconfigGenerator { return exactGenerator(t, rc, nil) }},
	} {
		for _, ttl := range []struct {
			asked, granted time.Duration
		}{
			{15 * time.Minute, 15 * time.Minute},
			{2 * time.Minute, MinCertDuration},
		} {
			t.Run(tc.name+"/"+ttl.asked.String(), func(t *testing.T) {
				api, rc := newStoreAPI(t, nil)
				before := time.Now()
				issued, err := tc.gen(t, rc).GenerateDelegated(storage.StrategyOIDC,
					userAs("alice", "kc", "a", "devs", "ops"), "dispatcher", "claim-a", ttl.asked)
				require.NoError(t, err)

				name := endpoints.DelegatedSecretName("alice", "dispatcher")
				assert.Equal(t, name, issued.Secret.Name)
				assert.Nil(t, issued.Kubeconfig)
				assert.Equal(t, []string{"POST " + name}, api.written, "only the delegated Secret")
				assert.WithinDuration(t, before.Add(ttl.granted), issued.NotAfter, 5*time.Second)

				sec := readBack(api.stored[name])
				assert.Equal(t, endpoints.DelegatedCredentialHeld,
					endpoints.CheckDelegatedCredential(sec, "alice", "dispatcher", []string{"devs", "ops"}, time.Now()))
				assert.Equal(t, "claim-a", sec.Annotations[storage.ClaimAnnotation])
				assert.Equal(t, "oidc", sec.Annotations[storage.StrategyAnnotation])
				assert.Empty(t, sec.Labels)
			})
		}
	}
}

// Nothing is minted for a delegated credential that couldn't be the token's:
// a reserved group is refused, never dropped, and an actor is required.
func TestGenerateDelegatedRefusesBeforeMinting(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	api, rc := newStoreAPI(t, nil)
	gen := legacyGenerator(t, rc)

	_, err := gen.GenerateDelegated(storage.StrategyOIDC, userAs("alice", "kc", "a", "devs", "krateo:loa:2"), "dispatcher", "c", time.Minute)
	require.Error(t, err)
	_, err = gen.GenerateDelegated(storage.StrategyOIDC, userAs("alice", "kc", "a", "devs"), "", "c", time.Minute)
	require.Error(t, err)
	assert.Equal(t, status.CauseIssuanceFailed, causeOf(err))
	assert.Empty(t, api.written)
}

func causeOf(err error) status.CauseType {
	var c status.CauseError
	if errors.As(err, &c) {
		return c.Cause
	}
	return ""
}

// SessionIdentity reads the identity an authn token's session credential
// records, by the guard's own reading of the username's Secrets.
func TestSessionIdentity(t *testing.T) {
	signedIn := ownedBy(t, "alice-clientconfig", "alice", map[string]string{
		storage.StrategyAnnotation: "ldap", storage.ClaimAnnotation: "claim-a"})
	unclaimed := ownedBy(t, "alice-clientconfig", "alice", map[string]string{storage.StrategyAnnotation: "basic"})
	noStrategy := ownedBy(t, "alice-clientconfig", "alice", map[string]string{storage.ClaimAnnotation: "claim-a"})
	bobs := ownedBy(t, "alice-clientconfig", "bob", map[string]string{
		storage.StrategyAnnotation: "ldap", storage.ClaimAnnotation: "claim-b"})

	for _, tc := range []struct {
		name     string
		username string
		lookup   *namesLookup
		strategy storage.Strategy
		claim    string
		refusal  Refusal
		cause    status.CauseType
	}{
		{"signed in", "alice", &namesLookup{secrets: map[string]*corev1.Secret{"alice-clientconfig": signedIn}}, "ldap", "claim-a", "", ""},
		{"no claim", "alice", &namesLookup{secrets: map[string]*corev1.Secret{"alice-clientconfig": unclaimed}}, "basic", "", "", ""},
		{"never signed in", "alice", &namesLookup{}, "", "", RefusalNotSignedIn, status.CauseSubjectNotSignedIn},
		{"no strategy", "alice", &namesLookup{secrets: map[string]*corev1.Secret{"alice-clientconfig": noStrategy}}, "", "", RefusalHeldLegacy, status.CauseUsernameUnavailable},
		{"another's Secret", "alice", &namesLookup{secrets: map[string]*corev1.Secret{"alice-clientconfig": bobs}}, "", "", RefusalClaimed, status.CauseUsernameUnavailable},
		{"no username", "", &namesLookup{}, "", "", RefusalNameMissing, status.CauseUsernameUnavailable},
		{"unreadable", "alice", &namesLookup{err: errors.New("down")}, "", "", "", status.CauseIssuanceFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			strategy, claim, err := SessionIdentity(t.Context(), tc.lookup, exact, zerolog.Nop(), tc.username)
			if tc.cause == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.strategy, strategy)
				assert.Equal(t, tc.claim, claim)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.refusal, RefusalOf(err))
			assert.Equal(t, tc.cause, causeOf(err))
		})
	}

	_, _, err := SessionIdentity(t.Context(), nil, exact, zerolog.Nop(), "alice")
	assert.Equal(t, status.CauseIssuanceFailed, causeOf(err))
}
