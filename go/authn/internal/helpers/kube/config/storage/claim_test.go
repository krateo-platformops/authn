package storage

import (
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// Two claims are the same identity exactly when their strings are equal,
// whatever the parts contain: an issuer and an ID can't be shifted into each
// other.
func TestEncodeClaimKeepsThePartsApart(t *testing.T) {
	assert.Equal(t, `["oidc","https://kc/realms/x","1"]`, EncodeClaim(StrategyOIDC, "https://kc/realms/x", "1"))
	assert.NotEqual(t, EncodeClaim(StrategyOIDC, "a:b", "c"), EncodeClaim(StrategyOIDC, "a", "b:c"))
	assert.NotEqual(t, EncodeClaim(StrategyLDAP, `corp","x`, "y"), EncodeClaim(StrategyLDAP, "corp", `x","y`))
}

// The claim is written on the session Secret, on create and on the update of
// an existing one, next to the strategy and groups.
func TestPutWritesTheClaim(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	claim := EncodeClaim(StrategyOAuth, "gh", "1001")
	for _, exists := range []bool{false, true} {
		// An existing Secret from before claims, with alice's certificate.
		rec := &putRecorder{exists: exists, existingCert: identityCert(t, "alice", nil)}
		store := Default(&rest.Config{Host: rec.serve(t).URL})
		w, err := store.Put("alice", &AuthInfo{Strategy: StrategyOAuth, Claim: claim,
			CertData: identityCert(t, "alice", []string{"tenants"})})
		require.NoError(t, err)
		require.NotEmpty(t, rec.written)
		// What Put reports is what an audit record names (AUDIT-4): the request
		// that stored the Secret, never the 409 step before an update.
		want := Written{Namespace: "krateo-system", Name: "alice-clientconfig", UID: "uid-stored", ResourceVersion: "7", Verb: "create", StatusCode: 201}
		if exists {
			want.Verb, want.StatusCode = "update", 200
		}
		assert.Equal(t, want, w, "exists=%v", exists)
		for _, sec := range rec.written {
			assert.Equal(t, claim, sec.Annotations[ClaimAnnotation], "exists=%v", exists)
			assert.Equal(t, "oauth", sec.Annotations[StrategyAnnotation])
		}
	}
}

// An existing Secret claimed by another identity is never overwritten: the
// write is refused with ErrClaimedByAnother, and nothing is stored. A Secret
// with no claim, or with the same one, is updated.
func TestPutRefusesASecretClaimedByAnother(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := EncodeClaim(StrategyOAuth, "gh", "1001")
	theirs := EncodeClaim(StrategyOAuth, "gh", "6666")
	nfo := func() *AuthInfo {
		return &AuthInfo{Strategy: StrategyOAuth, Claim: mine, CertData: identityCert(t, "alice", []string{"tenants"})}
	}

	rec := &putRecorder{exists: true, existing: map[string]string{ClaimAnnotation: theirs}}
	w, err := Default(&rest.Config{Host: rec.serve(t).URL}).Put("alice", nfo())
	require.ErrorIs(t, err, ErrClaimedByAnother)
	require.Len(t, rec.written, 1, "only the create that found the Secret; no update")
	assert.Equal(t, Written{Namespace: "krateo-system", Name: "alice-clientconfig", Verb: "update"}, w,
		"nothing stored: the update this login would have sent, no status, no uid")

	for _, existing := range []map[string]string{nil, {ClaimAnnotation: mine}, {StrategyAnnotation: "oauth"}} {
		rec := &putRecorder{exists: true, existing: existing, existingCert: identityCert(t, "alice", nil)}
		_, err := Default(&rest.Config{Host: rec.serve(t).URL}).Put("alice", nfo())
		require.NoError(t, err)
		assert.Len(t, rec.written, 2, "the create, then the update")
	}
}

// An unclaimed Secret, written before claims existed, is replaced only when
// its certificate was issued to this username: the derived name aliases
// usernames (john.doe's Secret is johndoe-clientconfig), and a Secret that
// holds another name's credential, or none it can read, is never overwritten.
// A claimed one is decided by its claim, as above.
func TestPutRefusesAnUnclaimedSecretItDoesntOwn(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	nfo := &AuthInfo{Strategy: StrategyOAuth, Claim: EncodeClaim(StrategyOAuth, "gh", "1001"),
		CertData: identityCert(t, "alice", []string{"tenants"})}
	for name, cert := range map[string]string{
		"another name's certificate":       identityCert(t, "al.ice", nil),
		"no certificate":                   "",
		"a certificate that doesn't parse": "garbage",
	} {
		t.Run(name, func(t *testing.T) {
			rec := &putRecorder{exists: true, existing: map[string]string{StrategyAnnotation: "oauth"}, existingCert: cert}
			w, err := Default(&rest.Config{Host: rec.serve(t).URL}).Put("alice", nfo)
			require.ErrorIs(t, err, ErrHeldByAnother)
			require.Len(t, rec.written, 1, "only the create that found the Secret; no update")
			assert.Equal(t, Written{Namespace: "krateo-system", Name: "alice-clientconfig", Verb: "update"}, w)
		})
	}
}

// Put's re-check with the names it aliases: john.doe updates its own
// pre-claim Secret (johndoe-clientconfig, certificate issued to john.doe);
// johndoe, whose name derives the same Secret, is refused. A step-up Secret
// is held to the same rule. A claimed Secret is decided by its claim alone,
// certificate or not.
func TestPutWithTheNamesItAliases(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	johnCert := identityCert(t, "john.doe", nil)
	put := func(name string, stepUp bool, existing map[string]string, cert string) (*putRecorder, error) {
		rec := &putRecorder{exists: true, existing: existing, existingCert: cert}
		_, err := Default(&rest.Config{Host: rec.serve(t).URL}).Put(name, &AuthInfo{Strategy: StrategyBasic, StepUp: stepUp,
			Claim: EncodeClaim(StrategyBasic, "krateo-system", name), CertData: identityCert(t, name, nil)})
		return rec, err
	}
	legacy := map[string]string{StrategyAnnotation: "basic"}

	rec, err := put("john.doe", false, legacy, johnCert)
	require.NoError(t, err, "the owner updates its Secret")
	assert.Len(t, rec.written, 2)

	rec, err = put("johndoe", false, legacy, johnCert)
	require.ErrorIs(t, err, ErrHeldByAnother, "the aliasing name is refused")
	assert.Len(t, rec.written, 1, "no update")

	rec, err = put("johndoe", true, legacy, johnCert)
	require.ErrorIs(t, err, ErrHeldByAnother, "the step-up Secret too")
	assert.Len(t, rec.written, 1)

	rec, err = put("johndoe", false, map[string]string{ClaimAnnotation: EncodeClaim(StrategyBasic, "krateo-system", "johndoe")}, "")
	require.NoError(t, err, "its own claim decides, with no certificate to read")
	assert.Len(t, rec.written, 2)
}
