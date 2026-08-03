package v1alpha1

import (
	authnoauth "github.com/krateo-platformops/authn/apis/authn/oauth"
	"github.com/krateo-platformops/authn/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OAuthConfigSpec struct {
	authnoauth.ConfigSpec `json:",inline"`
	RESTActionRef         *core.ObjectRef `json:"restActionRef,omitempty"`
	//+optional
	Graphics *core.Graphics `json:"graphics,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={krateo,authn,oauth}

// OAuthConfig is a AuthN Service OAuth configuration.
type OAuthConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OAuthConfigSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// OAuthConfigList contains a list of OAuthConfig
type OAuthConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuthConfig `json:"items"`
}
