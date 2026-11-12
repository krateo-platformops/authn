package v1alpha1

import (
	"github.com/krateo-platformops/authn/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type UserSpec struct {
	// Password is the reference to the secret with the user password.
	PasswordRef *core.SecretKeySelector `json:"passwordRef"`

	// DisplayName is the user full name.
	DisplayName string `json:"displayName"`

	// AvatarURL is the user avatar image url.
	AvatarURL string `json:"avatarURL"`

	// Groups the groups user belongs to.
	Groups []string `json:"groups,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={krateo,authn,user}
// metadata.name is the issued username, and authn names the user's Secret
// after it through plumbing's kubeutil.MakeDNS1123Compatible. The rule admits
// at create exactly the names that transform leaves unchanged, so a new name
// can't get a Secret, or a tenant, under another name (#140). It is checked
// only at create (oldSelf.hasValue() is true on every update): the name is
// immutable, and an existing object with such a name must stay updatable,
// which CRD validation ratcheting doesn't give a root-level rule.
// apis/names_test.go proves the pattern is the transform's.
// +kubebuilder:validation:XValidation:rule="oldSelf.hasValue() || self.metadata.name.matches('^[a-z0-9][-a-z0-9]{0,62}$')",message="the name must be a lowercase DNS-1123 label of at most 63 characters (a-z, 0-9, '-', starting with a letter or digit): authn names the user's Secret after it, and would rewrite any other name",optionalOldSelf=true

// User is a AuthN Service user configuration.
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec UserSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// UserList contains a list of User
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []User `json:"items"`
}
