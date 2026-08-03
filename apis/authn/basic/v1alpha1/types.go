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
