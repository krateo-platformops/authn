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

	// Delegation lets this service act for a signed-in person through
	// POST /delegate: it exchanges that person's authn JWT for a short-lived
	// one that names the person as subject and this service as actor (RFC 8693
	// "act"). Omitted, or allowed false: the service can't delegate.
	// See docs/design/agent-delegation.md.
	// +optional
	Delegation *Delegation `json:"delegation,omitempty"`

	// Principal is the kind of identity this service is, signed into every
	// token it obtains as the "principal" claim, so an audit record can say
	// what acted: agent (an AI agent), controller (a reconciler, such as a
	// composition controller) or service (any other workload). Omitted: service.
	// +optional
	// +kubebuilder:validation:Enum=agent;controller;service
	Principal string `json:"principal,omitempty"`
}

// Delegation is a service's opt-in to act for people.
type Delegation struct {
	// Allowed opts the service in.
	Allowed bool `json:"allowed"`

	// MaxDepth caps the actor chain of a token this service obtains, its own
	// link included: 1 means it may act only for a person directly, 3 that up
	// to two other services may stand between them. Default 3.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=8
	MaxDepth *int32 `json:"maxDepth,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={krateo,authn}

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
