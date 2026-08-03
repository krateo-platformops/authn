package apis

import (
	basicv1alpha1 "github.com/krateo-platformops/authn/apis/authn/basic/v1alpha1"
	oauthv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oauth/v1alpha1"
	serviceaccountv1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AddToSchemes may be used to add all resources defined in the project to a Scheme
var AddToSchemes runtime.SchemeBuilder

// AddToScheme adds all Resources to the Scheme
func AddToScheme(s *runtime.Scheme) error {
	return AddToSchemes.AddToScheme(s)
}

func init() {
	AddToSchemes = append(AddToSchemes,
		basicv1alpha1.SchemeBuilder.AddToScheme,
		oauthv1alpha1.SchemeBuilder.AddToScheme,
		serviceaccountv1alpha1.SchemeBuilder.AddToScheme,
	)
}
