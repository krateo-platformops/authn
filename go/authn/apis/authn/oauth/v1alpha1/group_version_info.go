// +kubebuilder:object:generate=true
// +groupName=oauth.authn.krateo.io
// +versionName=v1alpha1
package v1alpha1

import (
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// Package type metadata.
const (
	Group   = "oauth.authn.krateo.io"
	Version = "v1alpha1"
)

var (
	// SchemeGroupVersion is group version used to register these objects
	SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}
)

// OAuthConfig type metadata.
var (
	OAuthConfigKind             = reflect.TypeOf(OAuthConfig{}).Name()
	OAuthConfigGroupKind        = schema.GroupKind{Group: Group, Kind: OAuthConfigKind}.String()
	OAuthConfigKindAPIVersion   = OAuthConfigKind + "." + SchemeGroupVersion.String()
	OAuthConfigGroupVersionKind = SchemeGroupVersion.WithKind(OAuthConfigKind)
)

func init() {
	SchemeBuilder.Register(&OAuthConfig{}, &OAuthConfigList{})
}
