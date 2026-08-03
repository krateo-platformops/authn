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

	//+optional
	Graphics *core.Graphics `json:"graphics,omitempty"`
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
