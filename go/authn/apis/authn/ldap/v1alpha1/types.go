package v1alpha1

import (
	"github.com/krateo-platformops/authn/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LDAPConfigSpec struct {
	// DialURL: LDAP Server address.
	DialURL string `json:"dialURL"`

	// BindDN: specifies the username of the bind user
	// not necessary if the LDAP server supports anonymous searches.
	// +optional
	BindDN *string `json:"bindDN,omitempty"`

	// BindSecret: specifies the password of the bind user
	// not necessary if the LDAP server supports anonymous searches.
	// +optional
	BindSecret *core.SecretKeySelector `json:"bindSecret,omitempty"`

	// Filter for the search. This specifies criteria to use to identify which
	// entries within the scope should be returned.
	//Filter string `json:"filter"`

	// BaseDN: specifies the base of the subtree in which the search is to be constrained.
	BaseDN string `json:"baseDN"`

	TLS *bool `json:"tls,omitempty"`

	// GroupSearch configures how a user's groups are found after their bind
	// succeeds. Omitted, every field takes its default.
	//+optional
	GroupSearch *LDAPGroupSearch `json:"groupSearch,omitempty"`

	//+optional
	Graphics *core.Graphics `json:"graphics,omitempty"`
}

// LDAPGroupSearch configures the search for a user's groups (#72). Each
// entry the search returns is one group, named by its NameAttribute.
type LDAPGroupSearch struct {
	// BaseDN is the base of the subtree the group search is constrained to.
	// Default: spec.baseDN.
	//+optional
	BaseDN string `json:"baseDN,omitempty"`

	// Filter selects the user's groups. It is a Go text/template over the
	// authenticated user, with two fields: .DN, the DN the user bound as, and
	// .Username, the login name. Both are already escaped for an LDAP filter.
	// Default: member or uniqueMember equal to .DN, which covers
	// groupOfNames, Active Directory and groupOfUniqueNames. For posixGroup,
	// match memberUid to .Username. A template that doesn't parse, or that
	// doesn't render a valid LDAP filter, fails every login with a 500
	// (LDAPConfigInvalid). See docs/api.md for examples.
	//+optional
	Filter string `json:"filter,omitempty"`

	// NameAttribute is the group entry attribute whose value is the group's
	// name. A group entry without it is skipped. Default: cn.
	//+optional
	NameAttribute string `json:"nameAttribute,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={krateo,authn,ldap}

// LDAPConfig is a AuthN Service LDAP configuration.
type LDAPConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec LDAPConfigSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// LDAPConfigList contains a list of LDAPConfig
type LDAPConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LDAPConfig `json:"items"`
}
