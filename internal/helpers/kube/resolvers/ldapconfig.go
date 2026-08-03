package resolvers

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	ldapv1alpha1 "github.com/krateo-platformops/authn/apis/authn/ldap/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/client"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
)

func LDAPConfigGet(rc *rest.Config, name string) (*ldapv1alpha1.LDAPConfig, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	cli, err := client.New(rc, schema.GroupVersion{
		Group:   ldapv1alpha1.Group,
		Version: ldapv1alpha1.Version,
	})
	if err != nil {
		return nil, err
	}

	res := &ldapv1alpha1.LDAPConfig{}
	err = cli.Get().Resource("ldapconfigs").
		Namespace(ns).Name(name).
		Do(context.Background()).
		Into(res)

	return res, err
}

func LDAPConfigList(rc *rest.Config) (*ldapv1alpha1.LDAPConfigList, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	cli, err := client.New(rc, schema.GroupVersion{
		Group:   ldapv1alpha1.Group,
		Version: ldapv1alpha1.Version,
	})
	if err != nil {
		return nil, err
	}

	res := &ldapv1alpha1.LDAPConfigList{}
	err = cli.Get().Resource("ldapconfigs").
		Namespace(ns).
		Do(context.Background()).
		Into(res)

	return res, err
}
