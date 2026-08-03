package resolvers

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	oauthv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oauth/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/client"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
)

func GetOAuthConfig(rc *rest.Config, name string) (*oauthv1alpha1.OAuthConfig, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	cli, err := client.New(rc, schema.GroupVersion{
		Group:   oauthv1alpha1.Group,
		Version: oauthv1alpha1.Version,
	})
	if err != nil {
		return nil, err
	}

	res := &oauthv1alpha1.OAuthConfig{}
	err = cli.Get().Resource("oauthconfigs").
		Namespace(ns).Name(name).
		Do(context.Background()).
		Into(res)

	return res, err
}
