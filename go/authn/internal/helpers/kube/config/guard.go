package config

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
)

// systemGroupPrefix is Kubernetes' reserved group prefix.
const systemGroupPrefix = "system:"

// NameLookup reads the cluster facts the name guard decides from.
type NameLookup interface {
	// SessionSecret returns username's session credential Secret, or nil
	// when there is none.
	SessionSecret(ctx context.Context, username string) (*corev1.Secret, error)
	// Secret returns the Secret named name in authn's namespace, or nil when
	// there is none. It tells a refused or failed issuance which write it
	// would have sent (AUDIT-4).
	Secret(ctx context.Context, name string) (*corev1.Secret, error)
	// Provisioned reports whether an administrator created an identity with
	// this name in authn's namespace: a basic User or a ServiceAccount
	// mapping.
	Provisioned(ctx context.Context, username string) (bool, error)
	// BoundAsUser reports whether any RoleBinding or ClusterRoleBinding in
	// the cluster names username as a User subject.
	BoundAsUser(ctx context.Context, username string) (bool, error)
}

// nameGuard decides whether a username may be issued to an identity. A
// username grants whatever the cluster grants to that name, so it must never
// reach an identity it wasn't meant for:
//   - A username issued before is issued again only to the identity recorded
//     in its claim (storage.ClaimAnnotation).
//   - A Secret written before claims existed is adopted by the first login of
//     the strategy that wrote it. An administrator-provisioned identity (basic,
//     serviceaccount) also adopts a Secret whose strategy is unknown: the
//     administrator chose its name.
//   - An identity source (ldap, oauth, oidc) chooses its own usernames, so
//     it may not take a reserved name, a name an administrator provisioned,
//     or a name any RBAC binding already grants rights to, unless the name is
//     already claimed by this same identity.
type nameGuard struct {
	lookup NameLookup
	log    zerolog.Logger
}

// fromIdentitySource reports whether the strategy's usernames come from an
// identity source rather than from an administrator.
func fromIdentitySource(strategy storage.Strategy) bool {
	switch strategy {
	case storage.StrategyLDAP, storage.StrategyOAuth, storage.StrategyOIDC:
		return true
	}
	return false
}

// reservedNames and reservedPrefixes are usernames an identity source may never
// take, whether or not any binding names them yet: the names Kubernetes and the
// managed platforms give their own components, and administrator names. The
// RBAC check is the general rule; this list covers names the cluster may grant
// rights to later.
var (
	reservedNames    = []string{"admin", "administrator", "root", "masterclient", "nodeclient", "aksservice"}
	reservedPrefixes = []string{"system", "kube-", "kubelet", "cluster-", "gke-", "eks-", "aks-"}
)

// reservedName reports whether username is one an identity source may not take.
func reservedName(username string) bool {
	for _, n := range reservedNames {
		if username == n {
			return true
		}
	}
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(username, p) {
			return true
		}
	}
	return false
}

// checkSystemGroups refuses an identity carrying a `system:` group, whatever
// the strategy: such a group would grant what Kubernetes reserves for itself.
func checkSystemGroups(user userinfo.Info) error {
	for _, g := range user.GetGroups() {
		if strings.HasPrefix(g, systemGroupPrefix) {
			return refused(RefusalSystemGroup, status.Refused(status.CauseSystemGroupNotAllowed,
				fmt.Errorf("group %q can't be issued: the %s prefix is reserved to Kubernetes", g, systemGroupPrefix)))
		}
	}
	return nil
}

// admit returns the claim to record for user, or the refusal. It reads the
// cluster, so it runs after every check that doesn't.
func (g *nameGuard) admit(ctx context.Context, strategy storage.Strategy, user userinfo.Info) (string, error) {
	username := user.GetUserName()
	subject := user.GetSubject()
	if username == "" {
		return "", status.Refused(status.CauseUsernameUnavailable, errors.New("the identity has no username"))
	}
	if subject.ID == "" {
		// Every login sets the subject. One that didn't can't be told apart
		// from any other identity, so nothing is issued.
		return "", status.Failed(status.CauseIssuanceFailed, fmt.Errorf("the %s login set no subject for %q", strategy, username))
	}
	claim := storage.EncodeClaim(strategy, subject.Issuer, subject.ID)
	external := fromIdentitySource(strategy)

	refuse := func(why Refusal, reason string, args ...any) error {
		private := fmt.Errorf("username %q: "+reason, append([]any{username}, args...)...)
		g.log.Warn().Str("username", username).Str("strategy", string(strategy)).Str("claim", claim).
			Str("reason", private.Error()).Msg("username refused")
		return refused(why, status.RefusedPrivately(status.CauseUsernameUnavailable,
			fmt.Errorf("the username %q isn't available to this identity", username), private))
	}
	failed := func(err error) error {
		return status.Failed(status.CauseIssuanceFailed, fmt.Errorf("checking username %q: %w", username, err))
	}

	if external && reservedName(username) {
		return "", refuse(RefusalReserved, "reserved")
	}

	sec, err := g.lookup.SessionSecret(ctx, username)
	if err != nil {
		return "", failed(err)
	}
	if sec != nil {
		ann := sec.GetAnnotations()
		if have := ann[storage.ClaimAnnotation]; have != "" {
			if have == claim {
				return claim, nil
			}
			return "", refuse(RefusalClaimed, "claimed by another identity (%s)", have)
		}
		// Written before claims existed: the strategy that wrote it adopts it.
		wrote := storage.Strategy(ann[storage.StrategyAnnotation])
		if wrote == strategy {
			g.log.Info().Str("username", username).Str("strategy", string(strategy)).Str("claim", claim).
				Msg("username claimed by its first login since claims exist")
			return claim, nil
		}
		if !external && (wrote == "" || wrote == storage.StrategyUnknown) {
			g.log.Info().Str("username", username).Str("strategy", string(strategy)).Str("claim", claim).
				Msg("username claimed by its provisioned identity")
			return claim, nil
		}
		return "", refuse(RefusalHeldLegacy, "its Secret was written by %q, not by a %s login", wrote, strategy)
	}

	if !external {
		return claim, nil
	}
	provisioned, err := g.lookup.Provisioned(ctx, username)
	if err != nil {
		return "", failed(err)
	}
	if provisioned {
		return "", refuse(RefusalProvisioned, "an administrator provisioned it as a basic User or ServiceAccount mapping")
	}
	bound, err := g.lookup.BoundAsUser(ctx, username)
	if err != nil {
		return "", failed(err)
	}
	if bound {
		return "", refuse(RefusalBound, "a RoleBinding or ClusterRoleBinding already grants rights to it")
	}
	return claim, nil
}
