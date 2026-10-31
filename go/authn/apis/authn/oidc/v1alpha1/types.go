package v1alpha1

import (
	"github.com/krateo-platformops/authn/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OIDCConfigSpec struct {
	//+optional
	DiscoveryURL string `json:"discoveryURL"`

	// Issuer is the expected `iss` of the ID token. Required when
	// discoveryURL is not set; otherwise it is read from the discovery
	// document, and if set here it must equal the discovered one.
	// An OIDCConfig with neither refuses logins.
	//+optional
	Issuer string `json:"issuer,omitempty"`

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

	// StepUp enables POST /oidc/stepup for this provider: a login that proves
	// a higher assurance level (acr) gets a short-lived credential carrying
	// the group krateo:loa:2. Without it, step-up is refused.
	//+optional
	StepUp *OIDCStepUp `json:"stepUp,omitempty"`

	//+optional
	RESTActionRef *core.ObjectRef `json:"restActionRef,omitempty"`
	//+optional
	Graphics *core.Graphics `json:"graphics,omitempty"`
}

// OIDCStepUp configures step-up logins (#49).
type OIDCStepUp struct {
	// AcrValues are the ID token `acr` values that prove level of assurance
	// 2. A step-up whose acr is not listed is refused.
	// +kubebuilder:validation:MinItems=1
	AcrValues []string `json:"acrValues"`

	// MaxAge is how long ago the user may have authenticated (`auth_time`)
	// for a step-up to be granted. A long-lived SSO session at that level
	// is not enough on its own. Default 5m.
	//+optional
	MaxAge *metav1.Duration `json:"maxAge,omitempty"`

	// TTL is the requested lifetime of the step-up credential. It is never
	// renewed. Default 15m. The Kubernetes CSR API's minimum is 10m, and a
	// shorter TTL is refused.
	//+optional
	TTL *metav1.Duration `json:"ttl,omitempty"`
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
