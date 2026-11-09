package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// OwnerReference is the reference that ties a service identity's clientconfig
// Secret to this mapping, by its current UID, so the Kubernetes garbage
// collector deletes the credential once the mapping is retired. It is neither
// a controller reference nor blocking: authn doesn't manage the mapping, and
// blockOwnerDeletion would need rights on the mapping's finalizers that authn
// doesn't hold.
func (m *ServiceAccount) OwnerReference() metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: SchemeGroupVersion.String(),
		Kind:       ServiceAccountKind,
		Name:       m.Name,
		UID:        m.UID,
	}
}
