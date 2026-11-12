package storage

import (
	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/plumbing/endpoints"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/krateo-platformops/plumbing/kubeutil/content"
	"github.com/krateo-platformops/plumbing/usernames"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// EnvExactUsernames turns on exact session-Secret names (authn#140). The
// chart renders it from exactUsernames.enabled, false by default.
const EnvExactUsernames = "AUTHN_EXACT_USERNAMES"

// The identity keys authn#144 adds to every Secret authn writes, with exact
// naming on (authn#140). acmp's tenant-policy design (§2.5, "The authn contract") selects
// and names tenants from them.
const (
	// UsernameAnnotation is the exact username the Secret holds the credential
	// of, from the authenticated identity (or, backfilled, the certificate's
	// CN), never from the Secret's name. Readers prove ownership with it
	// (endpoints.OwnsSecret).
	UsernameAnnotation = endpoints.UsernameAnnotation
	// PrincipalLabel is the kind of identity: human, service, agent or
	// controller (PrincipalFor).
	PrincipalLabel = "authn.krateo.io/principal"
	// UsernameLabelLabel is usernames.Bounded(username, UsernameLabelMaxLen):
	// the tenant policy names a tenant's namespace tenant-<value>.
	UsernameLabelLabel = "authn.krateo.io/username-label"
)

// UsernameLabelMaxLen is the bound of UsernameLabelLabel. It is FROZEN: the
// tenant policy names a namespace "tenant-" + the label, and a namespace name
// is a DNS-1123 label of at most 63 characters, so 63 - len("tenant-") = 56
// (acmp's tenant-policy design, §2.5, "Bound = 56"). Changing it, like
// changing usernames.Bounded, would label a person's new Secret differently
// from their old one, and needs a versioned migration planned with the
// tenant-policy owner.
const UsernameLabelMaxLen = 56

// Naming is how authn names a user's session and step-up Secrets, and how it
// recognises them. The zero value is the legacy naming authn has always used
// (endpoints.SecretName, the username made DNS-1123 compatible): nothing new
// is written and nothing new is checked. Exact is authn#140, behind
// AUTHN_EXACT_USERNAMES.
type Naming struct {
	// Exact names a session Secret endpoints.ExactSecretName(username) when it
	// can, reads it exact-then-legacy, uses a Secret only when
	// endpoints.OwnsSecret proves it is the username's, and stamps the
	// identity keys (UsernameAnnotation, PrincipalLabel, UsernameLabelLabel;
	// authn#144).
	Exact bool
}

// SessionName is the session Secret authn writes for username. With exact
// naming it is endpoints.ExactSecretName(username), unless that can't name
// it: an administrator-provisioned name longer than
// endpoints.MaxExactUsernameLength or not a DNS-1123 subdomain keeps its
// legacy name (an identity source's is refused before any write).
func (n Naming) SessionName(username string) string {
	if n.Exact {
		if name, ok := endpoints.ExactSecretName(username); ok {
			return name
		}
	}
	return ClientConfigSecretName(username)
}

// StepUpName is the step-up Secret authn writes for username: SessionName's
// rule, ending in endpoints.StepUpSuffix.
func (n Naming) StepUpName(username string) string {
	if n.Exact {
		if _, ok := endpoints.ExactSecretName(username); ok {
			return username + endpoints.StepUpSuffix
		}
	}
	return StepUpSecretName(username)
}

// SessionNames is the names a reader tries for username's session Secret, in
// order. Legacy naming has one. Exact naming is endpoints.SessionSecretNames:
// the exact name, then the legacy one when it differs; the first is always
// SessionName, the one authn writes.
func (n Naming) SessionNames(username string) []string {
	if n.Exact {
		return endpoints.SessionSecretNames(username)
	}
	return []string{ClientConfigSecretName(username)}
}

// Issuable reports whether username's Secrets can be named after it exactly
// (endpoints.ExactSecretName). Legacy naming issues every name.
func (n Naming) Issuable(username string) bool {
	if !n.Exact {
		return true
	}
	_, ok := endpoints.ExactSecretName(username)
	return ok
}

// Owns reports whether sec holds username's credential
// (endpoints.OwnsSecret: the username annotation, else the certificate's CN),
// whatever the naming. With legacy naming authn asks it only of a Secret with
// no claim (authn#148); with exact naming, of every Secret it reads or
// replaces (authn#140).
func (n Naming) Owns(sec *corev1.Secret, username string) bool {
	return endpoints.OwnsSecret(sec, username)
}

// PrincipalFor is the PrincipalLabel value of a credential strategy issued:
// human for a person's sign-in (basic, LDAP, OAuth, OIDC); for a
// ServiceAccount mapping, the principal it declares (agent, controller), or
// service, never human, whatever its groups (a mapping carrying the tenants
// group included); service for authn itself. A strategy that proves no kind,
// "unknown" above all, has none: the label is left off rather than guessed,
// and a policy selecting on it fails closed.
func PrincipalFor(strategy Strategy, declared string) (string, bool) {
	switch strategy {
	case StrategyBasic, StrategyLDAP, StrategyOAuth, StrategyOIDC:
		return string(jwtutil.PrincipalHuman), true
	case StrategyServiceAccount:
		if p := jwtutil.Principal(declared); p.Known() && p != jwtutil.PrincipalHuman {
			return string(p), true
		}
		return string(jwtutil.PrincipalService), true
	case StrategySelf:
		return string(jwtutil.PrincipalService), true
	}
	return "", false
}

// UsernameLabel is username's UsernameLabelLabel value, usernames.Bounded at
// UsernameLabelMaxLen, and false when that isn't a valid label value (an
// empty username, or one that doesn't start with [a-z0-9], which authn never
// issues): the label is then left off, and a policy requiring it fails closed.
func UsernameLabel(username string) (string, bool) {
	v := usernames.Bounded(username, UsernameLabelMaxLen)
	if len(validation.IsValidLabelValue(v)) > 0 {
		return "", false
	}
	return v, true
}

// ExactIdentity is the identity keys a Secret holding username's credential
// carries with exact naming on: the UsernameAnnotation, and the
// PrincipalLabel and UsernameLabelLabel when they have a value.
func ExactIdentity(strategy Strategy, declaredPrincipal, username string) (annotations, labels map[string]string) {
	annotations = map[string]string{UsernameAnnotation: username}
	labels = map[string]string{}
	if p, ok := PrincipalFor(strategy, declaredPrincipal); ok {
		labels[PrincipalLabel] = p
	}
	if v, ok := UsernameLabel(username); ok {
		labels[UsernameLabelLabel] = v
	}
	return annotations, labels
}

// ContentKeys is what of a credential Secret's metadata is authorization-
// bearing content with exact naming on: the audit schema's annotations
// (audit.AuthorizationAnnotations), the UsernameAnnotation, and the two labels
// the tenant policy selects and names tenants by. The labels are authn's own
// constants: audit declares no label list yet.
func ContentKeys() content.Keys {
	return content.Keys{
		Annotations: append(audit.AuthorizationAnnotations(), UsernameAnnotation),
		Labels:      []string{PrincipalLabel, UsernameLabelLabel},
	}
}

// AuthorizationDiffers reports whether a write from before to after changes
// authorization-bearing content, which an audit record is owed for (AUDIT-4).
// Legacy naming compares the annotations as authn always has
// (AuthorizationAnnotationsDiffer). Exact naming compares through plumbing's
// content.DiffersWith and ContentKeys, the labels included; a comparison that
// can't be made counts as a change, so a record is never skipped on doubt.
func (n Naming) AuthorizationDiffers(before, after *corev1.Secret) bool {
	if !n.Exact {
		return AuthorizationAnnotationsDiffer(before.GetAnnotations(), after.GetAnnotations())
	}
	differs, err := content.DiffersWith(before, after, ContentKeys())
	return err != nil || differs
}
