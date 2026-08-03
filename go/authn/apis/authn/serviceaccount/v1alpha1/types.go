package v1alpha1

import (
	"github.com/krateo-platformops/authn/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceAccountSpec maps a Kubernetes ServiceAccount to an authn service identity. It is
// the basic.User pattern with the credential swapped from a password to a Kubernetes SA
// token (verified via the TokenReview API instead of a password compare).
type ServiceAccountSpec struct {
	// ServiceAccountRef is the Kubernetes ServiceAccount allowed to exchange its (audience-
	// bound) token for this identity. The CR's existence is the allowlist; an SA with no
	// matching ServiceAccount CR cannot exchange.
	ServiceAccountRef *core.ObjectRef `json:"serviceAccountRef"`

	// Groups the issued service identity belongs to. They become the client certificate's
	// Organization (O=), so standard Kubernetes RBAC bound to these groups scopes the
	// identity. authn never authors RBAC.
	// +optional
	Groups []string `json:"groups,omitempty"`

	// DisplayName is a human-friendly name for the service identity.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={krateo,authn,serviceaccount}

// ServiceAccount is an AuthN service-identity mapping for Kubernetes intra-service auth.
// metadata.name is the issued username (exactly like basic.User).
type ServiceAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServiceAccountSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// ServiceAccountList contains a list of ServiceAccount.
type ServiceAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceAccount `json:"items"`
}
