package config

import (
	"context"
	"errors"
	"fmt"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
)

// VouchForExchange decides whether user, a person an identity provider
// verified through strategy and whom a service now exchanges for an authn
// token (/delegate, authn#155), may be issued that token. It runs what a
// sign-in runs before it would mint, and writes nothing:
//   - the identity's own groups: no system: group, and no krateo: group from
//     an identity source;
//   - opts' admission checks (an OIDCConfig's allowedGroups);
//   - the username: present, not reserved, and, with exact naming, one its
//     Secret can be named after;
//   - the claim-first rule (Diego, 2026-11-13). An exchange writes no
//     Secret, so unlike a sign-in it can never claim a name: the username's
//     credential Secret must already carry exactly this identity's claim,
//     written by the person's portal sign-in. Otherwise two identities could
//     each be exchanged as the same unclaimed name.
//
// It decides from the same Secrets a sign-in does (nameGuard.held). The
// claim-first refusals are:
//   - RefusalNotSignedIn: no Secret counts (the person never signed in),
//     403 SubjectNotSignedIn, which says what to do;
//   - RefusalClaimed: a Secret carries another identity's claim, the opaque
//     403 UsernameUnavailable;
//   - RefusalHeldLegacy: the Secrets carry no claim (written before claims),
//     the opaque 403 UsernameUnavailable.
//
// It returns the identity's claim.
func VouchForExchange(ctx context.Context, lookup NameLookup, naming storage.Naming, log zerolog.Logger,
	strategy storage.Strategy, user userinfo.Info, opts ...IssueOption) (string, error) {
	if err := storage.ValidateGroups(user.GetGroups()); err != nil {
		return "", err
	}
	if err := refuseGroups(strategy, user); err != nil {
		return "", err
	}
	if err := NewIssueOptions(opts...).CheckAdmit(user); err != nil {
		return "", err
	}

	username := user.GetUserName()
	subject := user.GetSubject()
	if username == "" {
		return "", refused(RefusalNameMissing, status.Refused(status.CauseUsernameUnavailable, errors.New("the identity has no username")))
	}
	if subject.ID == "" {
		return "", status.Failed(status.CauseIssuanceFailed, fmt.Errorf("the %s identity has no subject", strategy))
	}
	if lookup == nil {
		return "", status.Failed(status.CauseIssuanceFailed, errors.New("no name lookup to check the username's claim"))
	}
	claim := storage.EncodeClaim(strategy, subject.Issuer, subject.ID)
	external := fromIdentitySource(strategy)

	g := nameGuard{lookup: lookup, log: log, naming: naming}
	// Neither the log line nor the errors name the username or the claim:
	// the audit record of the refusal does.
	refuse := func(why Refusal, reason string, args ...any) error {
		private := fmt.Errorf("the username "+reason, args...)
		log.Warn().Str("strategy", string(strategy)).Str("refusal", string(why)).
			Str("reason", private.Error()).Msg("exchange refused")
		return refused(why, status.RefusedPrivately(status.CauseUsernameUnavailable, errUsernameUnavailable, private))
	}
	failed := func(err error) error {
		return status.Failed(status.CauseIssuanceFailed, fmt.Errorf("checking the username: %w", err))
	}
	if external && reservedName(username) {
		return "", refuse(RefusalReserved, "is reserved")
	}
	held, err := g.held(ctx, username, external, refuse, failed)
	if err != nil {
		return "", err
	}
	return claimFirst(held, claim, refuse)
}

// claimFirst decides an exchange from the username's held Secrets: another
// identity's claim on any refuses, as at a sign-in; this identity's claim
// admits; Secrets with no claim are held, not claimed; and none at all means
// the person never signed in.
func claimFirst(held []*corev1.Secret, claim string, refuse func(Refusal, string, ...any) error) (string, error) {
	if len(held) == 0 {
		return "", refused(RefusalNotSignedIn, status.Refused(status.CauseSubjectNotSignedIn,
			errors.New("the person has no credential yet: sign in to the portal once, then retry")))
	}
	mine := false
	for _, sec := range held {
		switch have := sec.GetAnnotations()[storage.ClaimAnnotation]; {
		case have == "":
		case have == claim:
			mine = true
		default:
			return "", refuse(RefusalClaimed, "is claimed by another identity")
		}
	}
	if !mine {
		return "", refuse(RefusalHeldLegacy, "has a credential written before claims existed, which no exchange adopts")
	}
	return claim, nil
}
