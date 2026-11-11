package storage

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/authn/internal/helpers/kube"
)

// Identity annotations record who a <username>-clientconfig Secret was issued to
// and how, so that policy (e.g. tenant onboarding) can decide from facts authn
// already knows instead of from a hand-kept list of names. They are metadata
// only: nothing secret is ever written here.
const (
	// StrategyAnnotation is the login strategy that issued the credential.
	StrategyAnnotation = "authn.krateo.io/strategy"
	// GroupsAnnotation lists the groups in the client certificate's O=, in
	// certificate order, one per line. Newline-separated rather than
	// comma-joined because group names can contain commas (OIDC passes IdP
	// group names through verbatim). A CEL policy tests membership with
	// annotations['authn.krateo.io/groups'].split('\n').exists(g, g == 'x').
	GroupsAnnotation = "authn.krateo.io/groups"
	// ClaimAnnotation records the identity a username was issued to, as
	// EncodeClaim renders it. authn issues that username again only to the
	// same identity (see config's name guard).
	ClaimAnnotation = "authn.krateo.io/claim"

	groupSeparator = "\n"
)

// AuthorizationAnnotationsDiffer reports whether before and after disagree on
// any identity annotation authorization reads: policy decides from a
// credential's strategy and groups (tenant onboarding, for one), so changing
// them changes what the identity may do. A write that changes one of them is
// desired state, and an audit record (AUDIT-4) is owed for it even though the
// Secret's data is unchanged. The one declared list is the audit schema's
// (audit.AuthorizationAnnotations, schema v1's content_annotations), which the
// content hash counts too; callers compare through it, never ad hoc keys.
func AuthorizationAnnotationsDiffer(before, after map[string]string) bool {
	for _, k := range audit.AuthorizationAnnotations() {
		if before[k] != after[k] {
			return true
		}
	}
	return false
}

// Strategy is the value of StrategyAnnotation.
type Strategy string

const (
	StrategyBasic          Strategy = "basic"
	StrategyLDAP           Strategy = "ldap"
	StrategyOAuth          Strategy = "oauth"
	StrategyOIDC           Strategy = "oidc"
	StrategyServiceAccount Strategy = "serviceaccount"
	// StrategySelf is authn's own identity (authn-clientconfig), which authn
	// mints for itself and no login strategy creates.
	StrategySelf Strategy = "self"
	// StrategyUnknown is written only by the backfill of Secrets that predate
	// these annotations, when the issuing strategy cannot be proven.
	StrategyUnknown Strategy = "unknown"
)

// ValidateGroups rejects group names that GroupsAnnotation cannot represent
// unambiguously. It runs before a certificate is minted, so an identity whose
// groups cannot be recorded faithfully is refused rather than issued with a
// misleading annotation.
func ValidateGroups(groups []string) error {
	for _, g := range groups {
		if strings.Contains(g, groupSeparator) {
			return fmt.Errorf("group %q contains a newline; it cannot be recorded in %s", g, GroupsAnnotation)
		}
	}
	return nil
}

// IdentityAnnotations derives the identity annotations of a stored credential.
// The groups are read from the certificate itself (its O=), so the annotation
// states exactly what the credential grants, whoever wrote the Secret.
func IdentityAnnotations(strategy Strategy, certData string) (map[string]string, error) {
	if strategy == "" {
		return nil, fmt.Errorf("identity annotations: empty strategy")
	}

	crt, err := kube.ParseCertificateBase64(certData)
	if err != nil {
		return nil, fmt.Errorf("identity annotations: %w", err)
	}

	groups := crt.Subject.Organization
	if err := ValidateGroups(groups); err != nil {
		return nil, err
	}

	return map[string]string{
		StrategyAnnotation: string(strategy),
		GroupsAnnotation:   strings.Join(groups, groupSeparator),
	}, nil
}

// SplitGroups is the inverse of the GroupsAnnotation encoding.
func SplitGroups(v string) []string {
	if v == "" {
		return []string{}
	}
	return strings.Split(v, groupSeparator)
}

// EncodeClaim renders the identity a username is issued to: the strategy, the
// subject's issuer and its ID, as a JSON array. JSON keeps the three apart
// whatever they contain (an OIDC issuer is a URL, an LDAP DN has commas), so
// two claims are the same identity exactly when their strings are equal.
func EncodeClaim(strategy Strategy, issuer, id string) string {
	b, _ := json.Marshal([]string{string(strategy), issuer, id})
	return string(b)
}
