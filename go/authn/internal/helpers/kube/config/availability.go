package config

import (
	"context"
	"errors"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/plumbing/usernames"
)

// Unavailable is why a username can't be given to a new identity (POST
// /usernames/check): the reasons a sign-in's name guard refuses, plus a name
// authn would never issue.
type Unavailable string

const (
	// UnavailableInvalid: not a username authn issues (empty, too long, or
	// not in the DNS-1123 form; plumbing usernames.Check).
	UnavailableInvalid Unavailable = "invalid"
	// UnavailableReserved: a name reserved to Kubernetes or the platform.
	UnavailableReserved Unavailable = "reserved"
	// UnavailableClaimed: an identity holds the name's claim.
	UnavailableClaimed Unavailable = "name_claimed"
	// UnavailableHeldLegacy: a Secret written before claims existed holds the
	// name.
	UnavailableHeldLegacy Unavailable = "name_held_legacy"
	// UnavailableProvisioned: an administrator provisioned the name as a basic
	// User or ServiceAccount mapping.
	UnavailableProvisioned Unavailable = "name_provisioned"
	// UnavailableBound: a RoleBinding or ClusterRoleBinding names it as a User.
	UnavailableBound Unavailable = "name_bound"
)

// Unavailables lists every Unavailable, for a caller that maps them.
var Unavailables = []Unavailable{UnavailableInvalid, UnavailableReserved, UnavailableClaimed,
	UnavailableHeldLegacy, UnavailableProvisioned, UnavailableBound}

// CheckUsername reports whether username could be given to a new identity
// from an identity source, which doesn't exist yet: "" when it is available,
// else why not. It reads what the name guard reads, in the guard's order, and
// writes nothing.
//
// It is stricter than a sign-in on one point, deliberately: with no identity
// to compare, ANY existing <username>-clientconfig makes the name unavailable.
// A sign-in would admit the identity whose claim it carries, or let the
// strategy that wrote a pre-claims Secret adopt it; neither is a new person,
// and an access request must never hand an existing user's name to someone
// else.
//
// An error is a lookup that failed: the caller can't know, so it must treat
// the name as unavailable and retry.
func CheckUsername(ctx context.Context, lookup NameLookup, username string) (Unavailable, error) {
	why, _, err := CheckUsernameFor(ctx, lookup, username, "")
	return why, err
}

// ClaimedBy is whose claim holds a name, as CheckUsernameFor compares it with
// the claim a caller expects. It names no identity: only whether it is the
// expected one.
type ClaimedBy string

const (
	// ClaimedByYou: the name's claim is the expected one.
	ClaimedByYou ClaimedBy = "you"
	// ClaimedByAnother: the name's claim is someone else's.
	ClaimedByAnother ClaimedBy = "another"
)

// CheckUsernameFor is CheckUsername for a caller that expects a given
// identity to hold the name: expected is that identity's claim
// (storage.EncodeClaim), "" for none. When the name is claimed
// (UnavailableClaimed) and expected is set, it also reports whether the
// claim is expected's, so an access-request controller can tell that the
// person it created has signed in, without learning who else holds a name it
// doesn't. With expected "", or for any other answer, ClaimedBy is "".
func CheckUsernameFor(ctx context.Context, lookup NameLookup, username, expected string) (Unavailable, ClaimedBy, error) {
	if lookup == nil {
		return "", "", errors.New("no name lookup")
	}
	// Reserved first, so a reserved name is reported as such and not as an
	// invalid shape (usernames.Check refuses both).
	if username != "" && reservedName(username) {
		return UnavailableReserved, "", nil
	}
	if err := usernames.Check(username); err != nil {
		return UnavailableInvalid, "", nil
	}
	sec, err := lookup.SessionSecret(ctx, username)
	if err != nil {
		return "", "", err
	}
	if sec != nil {
		have := sec.GetAnnotations()[storage.ClaimAnnotation]
		if have == "" {
			return UnavailableHeldLegacy, "", nil
		}
		switch {
		case expected == "":
			return UnavailableClaimed, "", nil
		case have == expected:
			return UnavailableClaimed, ClaimedByYou, nil
		default:
			return UnavailableClaimed, ClaimedByAnother, nil
		}
	}
	provisioned, err := lookup.Provisioned(ctx, username)
	if err != nil {
		return "", "", err
	}
	if provisioned {
		return UnavailableProvisioned, "", nil
	}
	bound, err := lookup.BoundAsUser(ctx, username)
	if err != nil {
		return "", "", err
	}
	if bound {
		return UnavailableBound, "", nil
	}
	return "", "", nil
}
