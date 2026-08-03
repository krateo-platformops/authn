// +k8s:deepcopy-gen=package
package oauth

import "github.com/krateo-platformops/authn/apis/core"

type ConfigSpec struct {
	// ClientID is the application's ID.
	ClientID string `json:"clientID"`

	// ClientSecret is the application's secret.
	ClientSecretRef *core.SecretKeySelector `json:"clientSecretRef"`

	// AuthURL: oauth2 provider authorization URL
	AuthURL string `json:"authURL"`

	// TokenURL: oauth2 provider token exchange URL
	TokenURL string `json:"tokenURL"`

	// AuthStyle optionally specifies how the endpoint wants the
	// client ID & client secret sent. The zero value means to
	// auto-detect.
	// +optional
	// +kubebuilder:default=0
	AuthStyle *int `json:"authStyle,omitempty"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `json:"redirectURL"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes"`
}
