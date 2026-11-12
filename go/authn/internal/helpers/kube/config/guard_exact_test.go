package config

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/endpoints"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The X/Y pair of authn#140: john.doe's legacy name, johndoe-clientconfig, is
// johndoe's name.
const (
	userX   = "john.doe"
	userY   = "johndoe"
	exactX  = "john.doe-clientconfig"
	sharedY = "johndoe-clientconfig" // X's legacy name, Y's only name
)

var exact = storage.Naming{Exact: true}

// namesLookup holds Secrets by name and records every read, in order.
type namesLookup struct {
	secrets     map[string]*corev1.Secret
	provisioned bool
	bound       bool
	err         error

	asked []string
}

func (n *namesLookup) SessionSecret(context.Context, string) (*corev1.Secret, error) {
	n.asked = append(n.asked, "session")
	return nil, errors.New("exact naming reads names, not SessionSecret")
}

func (n *namesLookup) Secret(_ context.Context, name string) (*corev1.Secret, error) {
	n.asked = append(n.asked, name)
	if n.err != nil {
		return nil, n.err
	}
	return n.secrets[name], nil
}

func (n *namesLookup) Provisioned(context.Context, string) (bool, error) {
	n.asked = append(n.asked, "provisioned")
	return n.provisioned, nil
}

func (n *namesLookup) BoundAsUser(context.Context, string) (bool, error) {
	n.asked = append(n.asked, "bound")
	return n.bound, nil
}

// ownedBy is a session Secret holding username's certificate, written before
// authn#140 (no username annotation), with annotations.
func ownedBy(t *testing.T, name, username string, annotations map[string]string) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations},
		Data: map[string][]byte{storage.ClientCertLabel: []byte(certFor(t, username))}}
}

func certFor(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func claims(s storage.Strategy, id string) string { return storage.EncodeClaim(s, "kc", id) }

// An identity source's name its Secret can't be named after exactly is
// refused, name_not_issued, 403 UsernameUnavailable, before any read. An
// administrator-provisioned one isn't: it keeps its legacy name. With legacy
// naming nothing is refused for its shape.
func TestExactNamingRefusesAnIdentitySourceNameItCantIssue(t *testing.T) {
	notIssued := []string{"Alice.Smith", "alice_smith", "alice@corp", "-alice", "alice.", strings.Repeat("a", endpoints.MaxExactUsernameLength+1)}
	for _, strategy := range []storage.Strategy{storage.StrategyLDAP, storage.StrategyOAuth, storage.StrategyOIDC} {
		for _, name := range notIssued {
			l := &namesLookup{}
			_, err := (&nameGuard{lookup: l, log: zerolog.Nop(), naming: exact}).admit(context.Background(), strategy, userAs(name, "kc", "1"))
			require.Error(t, err, "%s %q", strategy, name)
			assert.Equal(t, RefusalNotIssued, RefusalOf(err), "%s %q", strategy, name)
			st := status.FromError(err)
			assert.Equal(t, http.StatusForbidden, st.Code)
			assert.Equal(t, status.CauseUsernameUnavailable, st.Details.Causes[0].Type)
			assert.Empty(t, l.asked, "%s %q: refused before any read", strategy, name)

			// Legacy naming: as main, no shape refusal.
			_, err = (&nameGuard{lookup: &fakeLookup{}, log: zerolog.Nop()}).admit(context.Background(), strategy, userAs(name, "kc", "1"))
			assert.NotEqual(t, RefusalNotIssued, RefusalOf(err), "legacy %s %q", strategy, name)
		}
		for _, name := range []string{userX, userY, strings.Repeat("a", endpoints.MaxExactUsernameLength)} {
			_, err := (&nameGuard{lookup: &namesLookup{}, log: zerolog.Nop(), naming: exact}).admit(context.Background(), strategy, userAs(name, "kc", "1"))
			assert.NoError(t, err, "%s %q is issued exactly", strategy, name)
		}
	}
	for _, strategy := range []storage.Strategy{storage.StrategyBasic, storage.StrategyServiceAccount} {
		for _, name := range notIssued {
			l := &namesLookup{}
			_, err := (&nameGuard{lookup: l, log: zerolog.Nop(), naming: exact}).admit(context.Background(), strategy, userAs(name, "kc", "1"))
			assert.NoError(t, err, "%s %q: provisioned names keep their legacy name", strategy, name)
			assert.Equal(t, []string{storage.ClientConfigSecretName(name)}, l.asked, "%s %q: read under its legacy name only", strategy, name)
		}
	}
}

// Exact naming reads the exact name, then the legacy one, never SessionSecret;
// legacy naming reads SessionSecret only, as main does.
func TestExactNamingReadsExactThenLegacy(t *testing.T) {
	l := &namesLookup{}
	_, err := (&nameGuard{lookup: l, log: zerolog.Nop(), naming: exact}).admit(context.Background(), storage.StrategyOIDC, userAs(userX, "kc", "x"))
	require.NoError(t, err)
	assert.Equal(t, []string{exactX, sharedY, "provisioned", "bound"}, l.asked)

	f := &fakeLookup{}
	_, err = (&nameGuard{lookup: f, log: zerolog.Nop()}).admit(context.Background(), storage.StrategyOIDC, userAs(userX, "kc", "x"))
	require.NoError(t, err)
	assert.Equal(t, []string{"secret", "provisioned", "bound"}, f.asked)
}

// The X/Y pair at the guard.
func TestExactNamingXYAtTheGuard(t *testing.T) {
	ctx := context.Background()
	x := userAs(userX, "kc", "x")
	y := userAs(userY, "kc", "y")
	guard := func(l NameLookup) *nameGuard { return &nameGuard{lookup: l, log: zerolog.Nop(), naming: exact} }

	// johndoe's Secret under john.doe's legacy name neither refuses john.doe
	// by its claim...
	l := &namesLookup{secrets: map[string]*corev1.Secret{
		sharedY: ownedBy(t, sharedY, userY, map[string]string{storage.ClaimAnnotation: claims(storage.StrategyOIDC, "y")}),
	}}
	claim, err := guard(l).admit(ctx, storage.StrategyOIDC, x)
	require.NoError(t, err, "johndoe's claim doesn't refuse john.doe")
	assert.Equal(t, claims(storage.StrategyOIDC, "x"), claim, "john.doe gets its own claim, not johndoe's")

	// ...nor admits it: a claim equal to john.doe's on johndoe's Secret
	// doesn't override john.doe's own exact name, claimed by another.
	l = &namesLookup{secrets: map[string]*corev1.Secret{
		exactX:  ownedBy(t, exactX, userX, map[string]string{storage.ClaimAnnotation: claims(storage.StrategyOIDC, "mallory")}),
		sharedY: ownedBy(t, sharedY, userY, map[string]string{storage.ClaimAnnotation: claims(storage.StrategyOIDC, "x")}),
	}}
	_, err = guard(l).admit(ctx, storage.StrategyOIDC, x)
	assert.Equal(t, RefusalClaimed, RefusalOf(err))

	// ...and an unclaimed one of another strategy doesn't refuse it either
	// (with legacy naming it would: name_held_legacy).
	l = &namesLookup{secrets: map[string]*corev1.Secret{sharedY: ownedBy(t, sharedY, userY, map[string]string{storage.StrategyAnnotation: "ldap"})}}
	_, err = guard(l).admit(ctx, storage.StrategyOIDC, x)
	assert.NoError(t, err)
	_, err = (&nameGuard{lookup: &fakeLookup{secret: l.secrets[sharedY]}, log: zerolog.Nop()}).admit(ctx, storage.StrategyOIDC, x)
	assert.Equal(t, RefusalHeldLegacy, RefusalOf(err), "legacy naming, as main: the shared Secret refuses")

	// johndoe: its only name holds john.doe's legacy Secret. Writing would
	// replace it, so johndoe is refused, whatever its claim says.
	for _, tc := range []struct {
		claim string
		want  Refusal
	}{
		{claims(storage.StrategyOIDC, "x"), RefusalClaimed},
		{claims(storage.StrategyOIDC, "y"), RefusalClaimed}, // even johndoe's own claim, on john.doe's Secret
		{"", RefusalHeldLegacy},
	} {
		ann := map[string]string{storage.StrategyAnnotation: "oidc"}
		if tc.claim != "" {
			ann[storage.ClaimAnnotation] = tc.claim
		}
		l = &namesLookup{secrets: map[string]*corev1.Secret{sharedY: ownedBy(t, sharedY, userX, ann)}}
		_, err = guard(l).admit(ctx, storage.StrategyOIDC, y)
		assert.Equal(t, tc.want, RefusalOf(err), "claim %q", tc.claim)
		assert.Equal(t, []string{sharedY}, l.asked, "decided at the first name")
	}

	// A Secret under johndoe's name with no certificate and no annotation
	// (one authn didn't write) isn't johndoe's: refused, never adopted, even
	// by a provisioned identity, with either naming (authn#148).
	l = &namesLookup{secrets: map[string]*corev1.Secret{sharedY: {ObjectMeta: metav1.ObjectMeta{Name: sharedY}}}}
	_, err = guard(l).admit(ctx, storage.StrategyBasic, y)
	assert.Equal(t, RefusalHeldLegacy, RefusalOf(err))
	_, err = (&nameGuard{lookup: &fakeLookup{secret: l.secrets[sharedY]}, log: zerolog.Nop()}).admit(ctx, storage.StrategyBasic, y)
	assert.Equal(t, RefusalHeldLegacy, RefusalOf(err), "legacy naming, as main since #148")
}

// Claim continuity: john.doe's own legacy Secret (johndoe-clientconfig
// holding john.doe's certificate) decides for john.doe: its claim admits that
// identity, with the same claim for the exact Secret, and refuses any other.
// A claim on either name decides.
func TestExactNamingCarriesTheClaimOfTheUsersLegacySecret(t *testing.T) {
	ctx := context.Background()
	mine, theirs := claims(storage.StrategyOIDC, "x"), claims(storage.StrategyOIDC, "mallory")
	x := userAs(userX, "kc", "x")
	for _, tc := range []struct {
		name    string
		secrets map[string]*corev1.Secret
		want    Refusal // "" admitted with mine
	}{
		{"its legacy Secret's claim", map[string]*corev1.Secret{
			sharedY: ownedBy(t, sharedY, userX, map[string]string{storage.ClaimAnnotation: mine})}, ""},
		{"another identity's claim on its legacy Secret", map[string]*corev1.Secret{
			sharedY: ownedBy(t, sharedY, userX, map[string]string{storage.ClaimAnnotation: theirs})}, RefusalClaimed},
		{"its pre-claims legacy Secret, written by its strategy", map[string]*corev1.Secret{
			sharedY: ownedBy(t, sharedY, userX, map[string]string{storage.StrategyAnnotation: "oidc"})}, ""},
		{"its pre-claims legacy Secret, written by another strategy", map[string]*corev1.Secret{
			sharedY: ownedBy(t, sharedY, userX, map[string]string{storage.StrategyAnnotation: "ldap"})}, RefusalHeldLegacy},
		{"its exact Secret's claim, the legacy one unclaimed", map[string]*corev1.Secret{
			exactX:  ownedBy(t, exactX, userX, map[string]string{storage.ClaimAnnotation: mine}),
			sharedY: ownedBy(t, sharedY, userX, map[string]string{storage.StrategyAnnotation: "ldap"})}, ""},
		{"its exact Secret's claim, another's on the legacy one", map[string]*corev1.Secret{
			exactX:  ownedBy(t, exactX, userX, map[string]string{storage.ClaimAnnotation: mine}),
			sharedY: ownedBy(t, sharedY, userX, map[string]string{storage.ClaimAnnotation: theirs})}, RefusalClaimed},
		{"owned by the username annotation", map[string]*corev1.Secret{
			exactX: {ObjectMeta: metav1.ObjectMeta{Name: exactX, Annotations: map[string]string{
				storage.UsernameAnnotation: userX, storage.ClaimAnnotation: mine}}}}, ""},
		{"an annotation naming another username is another's Secret", map[string]*corev1.Secret{
			exactX: {ObjectMeta: metav1.ObjectMeta{Name: exactX, Annotations: map[string]string{
				storage.UsernameAnnotation: userY, storage.ClaimAnnotation: mine}}}}, RefusalClaimed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := map[string]*corev1.Secret{}
			for k, v := range tc.secrets {
				before[k] = v.DeepCopy()
			}
			claim, err := (&nameGuard{lookup: &namesLookup{secrets: tc.secrets}, log: zerolog.Nop(), naming: exact}).admit(ctx, storage.StrategyOIDC, x)
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, mine, claim, "the claim the exact Secret is written with")
			} else {
				assert.Equal(t, tc.want, RefusalOf(err))
			}
			assert.Equal(t, before, tc.secrets, "the guard changes nothing it reads")
		})
	}
}

// A read that fails is authn's failure, 500, whichever name it was.
func TestExactNamingFailsClosedOnARead(t *testing.T) {
	_, err := (&nameGuard{lookup: &namesLookup{err: errors.New("down")}, log: zerolog.Nop(), naming: exact}).
		admit(context.Background(), storage.StrategyOIDC, userAs(userX, "kc", "x"))
	require.Error(t, err)
	assert.Equal(t, http.StatusInternalServerError, status.FromError(err).Code)
	assert.Empty(t, RefusalOf(err))
}

// The exact guard's lines, and the errors a route logs, name no one.
func TestExactNamingGuardLogsNoIdentity(t *testing.T) {
	ctx := context.Background()
	sentinelDotted := logtest.Marker + ".user" // legacy name zz-sentineluser-clientconfig
	for _, tc := range []struct {
		name     string
		strategy storage.Strategy
		user     string
		secrets  func(t *testing.T) map[string]*corev1.Secret
	}{
		{"not issued", storage.StrategyOIDC, "Zz-Sentinel.User", func(*testing.T) map[string]*corev1.Secret { return nil }},
		{"another username's Secret under its name", storage.StrategyOIDC, logtest.User, func(t *testing.T) map[string]*corev1.Secret {
			return map[string]*corev1.Secret{logtest.User + "-clientconfig": ownedBy(t, "x", sentinelDotted, map[string]string{storage.ClaimAnnotation: "c"})}
		}},
		{"its legacy Secret claimed by another", storage.StrategyOIDC, sentinelDotted, func(t *testing.T) map[string]*corev1.Secret {
			return map[string]*corev1.Secret{"zz-sentineluser-clientconfig": ownedBy(t, "x", sentinelDotted, map[string]string{storage.ClaimAnnotation: logtest.Marker + "-other"})}
		}},
		{"adopted: its pre-claims legacy Secret", storage.StrategyOIDC, sentinelDotted, func(t *testing.T) map[string]*corev1.Secret {
			return map[string]*corev1.Secret{"zz-sentineluser-clientconfig": ownedBy(t, "x", sentinelDotted, map[string]string{storage.StrategyAnnotation: "oidc"})}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs, l := logtest.Capture()
			_, err := (&nameGuard{lookup: &namesLookup{secrets: tc.secrets(t)}, log: l, naming: exact}).
				admit(ctx, tc.strategy, userAs(tc.user, "kc", logtest.Subject))
			logFailure(l, err)
			logtest.NoIdentity(t, logs)
		})
	}
}
