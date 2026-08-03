package resolvers

import (
	"context"
	"fmt"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/client"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// ServiceAccountForSA returns the ServiceAccount mapping whose spec.serviceAccountRef
// matches the given Kubernetes ServiceAccount (namespace/name). The CR's existence is the
// exchange allowlist: not-found means that SA may not exchange its token. The CR is looked
// up by listing the operator namespace and matching the ref (a CR's name is the issued
// username, which need not equal the SA name, so a name Get would not suffice).
func ServiceAccountForSA(rc *rest.Config, saNamespace, saName string) (*sav1alpha1.ServiceAccount, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	cli, err := client.New(rc, schema.GroupVersion{
		Group:   sav1alpha1.Group,
		Version: sav1alpha1.Version,
	})
	if err != nil {
		return nil, err
	}

	res := &sav1alpha1.ServiceAccountList{}
	err = cli.Get().Resource("serviceaccounts").
		Namespace(ns).
		Do(context.Background()).
		Into(res)
	if err != nil {
		return nil, err
	}

	var match *sav1alpha1.ServiceAccount
	for i := range res.Items {
		ref := res.Items[i].Spec.ServiceAccountRef
		if ref != nil && ref.Namespace == saNamespace && ref.Name == saName {
			if match != nil {
				return nil, fmt.Errorf("ambiguous mapping: multiple ServiceAccount resources reference %s/%s", saNamespace, saName)
			}
			match = &res.Items[i]
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no ServiceAccount mapping for serviceaccount %s/%s (not in the exchange allowlist)", saNamespace, saName)
	}
	return match, nil
}
