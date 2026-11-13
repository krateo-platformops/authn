package config

import "errors"

// Refusal is why authn refused a verified identity a credential: no username,
// the name guard's reasons, a system: or krateo: group, an OIDCConfig's
// allowedGroups, and a step-up the ID token doesn't prove. An audit record carries it as its
// closed-set denial reason (AUDIT-4); the HTTP answer stays opaque.
type Refusal string

const (
	// RefusalNameMissing: the identity source verified someone but gave no
	// username, so there is no name to issue or Secret to write.
	RefusalNameMissing Refusal = "name_missing"
	// RefusalReserved: an identity source asked for a reserved name.
	RefusalReserved Refusal = "name_reserved"
	// RefusalNotIssued: with exact naming (authn#140), an identity source
	// asked for a name its Secret can't be named after exactly
	// (endpoints.ExactSecretName: not a DNS-1123 subdomain, or longer than
	// endpoints.MaxExactUsernameLength). Its legacy name would be a rewrite,
	// which may be another username's.
	RefusalNotIssued Refusal = "name_not_issued"
	// RefusalClaimed: another identity holds the name's claim. A login that
	// loses the race to a simultaneous first login gets it too.
	RefusalClaimed Refusal = "name_claimed"
	// RefusalHeldLegacy: a Secret written before claims existed holds the
	// name, and either another strategy wrote it or its certificate wasn't
	// issued to this username.
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
	// RefusalStepUpNotEnabled: a step-up was asked of an OIDCConfig without
	// spec.stepUp.
	RefusalStepUpNotEnabled Refusal = "stepup_not_enabled"
	// RefusalInsufficientAssurance: the step-up's ID token has an acr that
	// isn't one of spec.stepUp.acrValues.
	RefusalInsufficientAssurance Refusal = "insufficient_assurance"
	// RefusalStaleAuthentication: the step-up's ID token has no auth_time, or
	// an authentication older than spec.stepUp.maxAge.
	RefusalStaleAuthentication Refusal = "stale_authentication"
	// RefusalNotSignedIn: a token exchange's subject verified, but their
	// username has no credential Secret, so no claim says the name is theirs
	// (authn#155): the person must sign in to the portal first.
	RefusalNotSignedIn Refusal = "subject_not_signed_in"
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
var Refusals = []Refusal{RefusalNameMissing, RefusalReserved, RefusalNotIssued, RefusalClaimed, RefusalHeldLegacy, RefusalProvisioned,
	RefusalBound, RefusalSystemGroup, RefusalGroupNotAllowed, RefusalPlatformGroup,
	RefusalStepUpNotEnabled, RefusalInsufficientAssurance, RefusalStaleAuthentication, RefusalNotSignedIn}

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
