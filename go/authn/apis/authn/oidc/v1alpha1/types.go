package v1alpha1

import (
	"github.com/krateo-platformops/authn/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OIDCConfigSpec struct {
	//+optional
	DiscoveryURL string `json:"discoveryURL"`

	//+optional
	AuthorizationURL string `json:"authorizationURL"`
	//+optional
	TokenURL string `json:"tokenURL"`
	//+optional
	UserInfoURL string `json:"userInfoURL"`

	RedirectURI string `json:"redirectURI"`

	ClientID     string                  `json:"clientID"`
	ClientSecret *core.SecretKeySelector `json:"clientSecret"`

	//+optional
	AdditionalScopes string `json:"additionalScopes"`

	//+optional
	RESTActionRef *core.ObjectRef `json:"restActionRef,omitempty"`
	//+optional
	Graphics *core.Graphics `json:"graphics,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={krateo,authn,oidc}

// OIDCConfig is a AuthN Service OIDC configuration.
type OIDCConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OIDCConfigSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// OIDCConfigList contains a list of OIDCConfig
type OIDCConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCConfig `json:"items"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IDToken     string `json:"id_token"`
}
