package secrets

import (
	"context"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/client"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

func Get(ctx context.Context, rc *rest.Config, sel *core.SecretKeySelector) (*corev1.Secret, error) {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return nil, err
	}

	res := &corev1.Secret{}
	err = cli.Get().
		Resource("secrets").
		Namespace(sel.Namespace).Name(sel.Name).
		Do(ctx).
		Into(res)

	return res, err
}

func Create(ctx context.Context, rc *rest.Config, secret *corev1.Secret) error {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return err
	}

	return cli.Post().
		Namespace(secret.GetNamespace()).
		Resource("secrets").
		Body(secret).
		Do(ctx).
		Error()
}

func CreateOrUpdate(ctx context.Context, rc *rest.Config, secret *corev1.Secret) error {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return err
	}

	// First try to get the secret
	existingSecret := &corev1.Secret{}
	err = cli.Get().
		Namespace(secret.GetNamespace()).
		Resource("secrets").
		Name(secret.GetName()).
		Do(ctx).
		Into(existingSecret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			// Secret doesn't exist, create it
			return cli.Post().
				Namespace(secret.GetNamespace()).
				Resource("secrets").
				Body(secret).
				Do(ctx).
				Error()
		}
		return err // Return any other error
	}

	secret.ResourceVersion = existingSecret.ResourceVersion
	// Secret exists, update it
	return cli.Put().
		Namespace(secret.GetNamespace()).
		Resource("secrets").
		Name(secret.GetName()).
		Body(secret).
		Do(ctx).
		Error()
}

func Update(ctx context.Context, rc *rest.Config, secret *corev1.Secret) error {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return err
	}
	return cli.Put().
		Namespace(secret.GetNamespace()).
		Resource("secrets").
		Name(secret.Name).
		Body(secret).
		Do(ctx).
		Error()
}

func Delete(ctx context.Context, rc *rest.Config, sel *core.SecretKeySelector) error {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return err
	}

	return cli.Delete().
		Namespace(sel.Namespace).
		Resource("secrets").
		Name(sel.Name).
		Do(ctx).
		Error()
}
