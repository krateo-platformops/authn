// +kubebuilder:object:generate=true
// +groupName=oidc.authn.krateo.io
// +versionName=v1alpha1
package v1alpha1

import (
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// Package type metadata.
const (
	Group   = "oidc.authn.krateo.io"
	Version = "v1alpha1"
)

var (
	// SchemeGroupVersion is group version used to register these objects
	SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}
)

// User type metadata.
var (
	OIDCConfigKind             = reflect.TypeOf(OIDCConfig{}).Name()
	OIDCConfigGroupKind        = schema.GroupKind{Group: Group, Kind: OIDCConfigKind}.String()
	OIDCConfigKindAPIVersion   = OIDCConfigKind + "." + SchemeGroupVersion.String()
	OIDCConfigGroupVersionKind = SchemeGroupVersion.WithKind(OIDCConfigKind)
)

func init() {
	SchemeBuilder.Register(&OIDCConfig{}, &OIDCConfigList{})
}
