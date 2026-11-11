package config

import "errors"

// Refusal is why authn refused a verified identity a credential: no username,
// the name guard's reasons, and a system: or krateo: group. An audit record carries it as its
// closed-set denial reason (AUDIT-4); the HTTP answer stays opaque.
type Refusal string

const (
	// RefusalNameMissing: the identity source verified someone but gave no
	// username, so there is no name to issue or Secret to write.
	RefusalNameMissing Refusal = "name_missing"
	// RefusalReserved: an identity source asked for a reserved name.
	RefusalReserved Refusal = "name_reserved"
	// RefusalClaimed: another identity holds the name's claim. A login that
	// loses the race to a simultaneous first login gets it too.
	RefusalClaimed Refusal = "name_claimed"
	// RefusalHeldLegacy: a Secret written before claims existed, by another
	// strategy, holds the name.
	RefusalHeldLegacy Refusal = "name_held_legacy"
	// RefusalProvisioned: an administrator provisioned the name as a basic User
	// or ServiceAccount mapping.
	RefusalProvisioned Refusal = "name_provisioned"
	// RefusalBound: a RoleBinding or ClusterRoleBinding names the name as a
	// User subject.
	RefusalBound Refusal = "name_bound"
	// RefusalSystemGroup: the identity carries a system: group.
	RefusalSystemGroup Refusal = "system_group"
	// RefusalGroupNotAllowed: the identity is in none of the groups its
	// provider admits (an OIDCConfig's allowedGroups).
	RefusalGroupNotAllowed Refusal = "group_not_allowed"
	// RefusalPlatformGroup: an identity source asserted a `krateo:` group.
	RefusalPlatformGroup Refusal = "platform_group"
)

// refusedError carries a Refusal beside the status error the caller answers
// with. It changes nothing about that answer: errors.As still finds the
// status error through it.
type refusedError struct {
	reason Refusal
	err    error
}

func (e refusedError) Error() string { return e.err.Error() }
func (e refusedError) Unwrap() error { return e.err }

func refused(reason Refusal, err error) error { return refusedError{reason: reason, err: err} }

// Refusals lists every Refusal, for a caller that maps them (the audit record's
// denial reason) to prove its map complete.
var Refusals = []Refusal{RefusalNameMissing, RefusalReserved, RefusalClaimed, RefusalHeldLegacy, RefusalProvisioned,
	RefusalBound, RefusalSystemGroup, RefusalGroupNotAllowed, RefusalPlatformGroup}

// Refused marks err, the status error a caller answers with, as a refusal of a
// verified identity for reason (see Admit).
func Refused(reason Refusal, err error) error { return refused(reason, err) }

// RefusalOf returns why err refused a verified identity, or "" when err is not
// such a refusal.
func RefusalOf(err error) Refusal {
	var r refusedError
	if errors.As(err, &r) {
		return r.reason
	}
	return ""
}
