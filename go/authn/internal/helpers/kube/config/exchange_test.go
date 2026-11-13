package config

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// VouchForExchange's decision table (authn#155): a sign-in's identity checks,
// then the claim-first rule. Only the username's Secret already carrying this
// identity's claim admits; never signing in says so (SubjectNotSignedIn), and
// another identity's or no claim is the opaque UsernameUnavailable.
func TestVouchForExchange(t *testing.T) {
	const iss = "https://kc.example/realms/krateo"
	mine := storage.EncodeClaim(storage.StrategyOIDC, iss, "uid-alice")
	theirs := storage.EncodeClaim(storage.StrategyOIDC, iss, "uid-mallory")
	alice := func(groups ...string) *userinfo.DefaultUser { return userAs("alice", iss, "uid-alice", groups...) }
	notAdmin := Admit(func(u userinfo.Info) error {
		for _, g := range u.GetGroups() {
			if g == "tenants" {
				return nil
			}
		}
		return Refused(RefusalGroupNotAllowed, status.Refused(status.CauseUsernameUnavailable, errors.New("not admitted")))
	})

	for _, tc := range []struct {
		name   string
		lookup NameLookup
		naming storage.Naming
		user   *userinfo.DefaultUser
		opts   []IssueOption
		want   Refusal // "" admits
		cause  status.CauseType
	}{
		{name: "the username's Secret carries this identity's claim", lookup: &fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: mine})},
			user: alice("tenants")},
		{name: "no Secret: never signed in", lookup: &fakeLookup{}, user: alice("tenants"),
			want: RefusalNotSignedIn, cause: status.CauseSubjectNotSignedIn},
		{name: "another identity's claim", lookup: &fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: theirs})}, user: alice(),
			want: RefusalClaimed, cause: status.CauseUsernameUnavailable},
		{name: "a Secret from before claims, the username's own certificate", lookup: &fakeLookup{secret: issuedTo(t, "alice", nil)}, user: alice(),
			want: RefusalHeldLegacy, cause: status.CauseUsernameUnavailable},
		{name: "a Secret from before claims, another username's certificate", lookup: &fakeLookup{secret: issuedTo(t, "Alice", nil)}, user: alice(),
			want: RefusalHeldLegacy, cause: status.CauseUsernameUnavailable},
		{name: "a krateo: group from the identity provider", lookup: &fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: mine})},
			user: alice("krateo:admins"), want: RefusalPlatformGroup, cause: status.CausePlatformGroupNotAllowed},
		{name: "a system: group", lookup: &fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: mine})},
			user: alice("system:masters"), want: RefusalSystemGroup, cause: status.CauseSystemGroupNotAllowed},
		{name: "the OIDCConfig's allowedGroups", lookup: &fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: mine})},
			user: alice("devs"), opts: []IssueOption{notAdmin}, want: RefusalGroupNotAllowed},
		{name: "a reserved name", lookup: &fakeLookup{}, user: userAs("admin", iss, "uid-admin"), want: RefusalReserved, cause: status.CauseUsernameUnavailable},
		{name: "no username", lookup: &fakeLookup{}, user: userAs("", iss, "uid-x"), want: RefusalNameMissing, cause: status.CauseUsernameUnavailable},

		// Exact naming (authn#140): the same Secrets a sign-in decides from.
		{name: "exact: the exact Secret carries this identity's claim", naming: exact,
			lookup: &namesLookup{secrets: map[string]*corev1.Secret{exactX: ownedBy(t, exactX, userX, map[string]string{storage.ClaimAnnotation: storage.EncodeClaim(storage.StrategyOIDC, iss, "uid-x")})}},
			user:   userAs(userX, iss, "uid-x")},
		{name: "exact: the username's own legacy Secret carries its claim", naming: exact,
			lookup: &namesLookup{secrets: map[string]*corev1.Secret{sharedY: ownedBy(t, sharedY, userX, map[string]string{storage.ClaimAnnotation: storage.EncodeClaim(storage.StrategyOIDC, iss, "uid-x")})}},
			user:   userAs(userX, iss, "uid-x")},
		{name: "exact: another username's legacy Secret under the legacy name is passed over: never signed in", naming: exact,
			lookup: &namesLookup{secrets: map[string]*corev1.Secret{sharedY: ownedBy(t, sharedY, userY, map[string]string{storage.ClaimAnnotation: theirs})}},
			user:   userAs(userX, iss, "uid-x"), want: RefusalNotSignedIn, cause: status.CauseSubjectNotSignedIn},
		{name: "exact: a name that can't be exact", naming: exact, lookup: &namesLookup{},
			user: userAs("Alice.Smith", iss, "uid-a"), want: RefusalNotIssued, cause: status.CauseUsernameUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim, err := VouchForExchange(context.Background(), tc.lookup, tc.naming, zerolog.Nop(), storage.StrategyOIDC, tc.user, tc.opts...)
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, storage.EncodeClaim(storage.StrategyOIDC, iss, tc.user.GetSubject().ID), claim)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.want, RefusalOf(err))
			assert.Empty(t, claim)
			st := status.FromError(err)
			assert.Equal(t, http.StatusForbidden, st.Code)
			if tc.cause != "" {
				require.NotEmpty(t, st.Details.Causes)
				assert.Equal(t, tc.cause, st.Details.Causes[0].Type)
			}
		})
	}
}

// A failed read is authn's failure (500), never a refusal; no lookup at all
// is a failure too.
func TestVouchForExchangeFailures(t *testing.T) {
	const iss = "https://kc.example/realms/krateo"
	_, err := VouchForExchange(context.Background(), &fakeLookup{err: errors.New("apiserver down")}, storage.Naming{}, zerolog.Nop(),
		storage.StrategyOIDC, userAs("alice", iss, "uid-alice"))
	require.Error(t, err)
	assert.Empty(t, RefusalOf(err))
	assert.Equal(t, http.StatusInternalServerError, status.FromError(err).Code)

	_, err = VouchForExchange(context.Background(), nil, storage.Naming{}, zerolog.Nop(), storage.StrategyOIDC, userAs("alice", iss, "uid-alice"))
	require.Error(t, err)
	assert.Equal(t, http.StatusInternalServerError, status.FromError(err).Code)
}
