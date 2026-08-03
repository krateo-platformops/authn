// +kubebuilder:object:generate=true
// +groupName=ldap.authn.krateo.io
// +versionName=v1alpha1
package v1alpha1

import (
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// Package type metadata.
const (
	Group   = "ldap.authn.krateo.io"
	Version = "v1alpha1"
)

var (
	// SchemeGroupVersion is group version used to register these objects
	SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}
)

// LDAPConfig type metadata.
var (
	LDAPConfigKind             = reflect.TypeOf(LDAPConfig{}).Name()
	LDAPConfigGroupKind        = schema.GroupKind{Group: Group, Kind: LDAPConfigKind}.String()
	LDAPConfigKindAPIVersion   = LDAPConfigKind + "." + SchemeGroupVersion.String()
	LDAPConfigGroupVersionKind = SchemeGroupVersion.WithKind(LDAPConfigKind)
)

func init() {
	SchemeBuilder.Register(&LDAPConfig{}, &LDAPConfigList{})
}
