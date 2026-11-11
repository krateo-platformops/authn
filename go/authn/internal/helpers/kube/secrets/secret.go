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

// List returns the Secrets in namespace.
func List(ctx context.Context, rc *rest.Config, namespace string) (*corev1.SecretList, error) {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return nil, err
	}

	res := &corev1.SecretList{}
	err = cli.Get().
		Resource("secrets").
		Namespace(namespace).
		Do(ctx).
		Into(res)

	return res, err
}

// Create creates secret and decodes the stored Secret back into it, so the
// caller holds its uid and resourceVersion. It returns the apiserver's HTTP
// status code (0 when no response arrived), which an audit record carries as
// the authority's answer.
func Create(ctx context.Context, rc *rest.Config, secret *corev1.Secret) (int, error) {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return 0, err
	}

	res := cli.Post().
		Namespace(secret.GetNamespace()).
		Resource("secrets").
		Body(secret).
		Do(ctx)
	return decodeInto(res, secret)
}

// decodeInto reads res's status code and, on success, decodes the stored
// Secret into secret. The write succeeded when res carries no error, and then
// the error is nil whatever happens next: an answer that can't be decoded only
// leaves secret as sent (no uid), so a done write never reads as failed.
func decodeInto(res rest.Result, secret *corev1.Secret) (int, error) {
	var code int
	res.StatusCode(&code)
	if err := res.Error(); err != nil {
		return code, err
	}
	stored := &corev1.Secret{}
	if err := res.Into(stored); err != nil {
		return code, nil
	}
	*secret = *stored
	return code, nil
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

// Update replaces secret (PUT) and decodes the stored Secret back into it. It
// returns the apiserver's HTTP status code, as Create does.
func Update(ctx context.Context, rc *rest.Config, secret *corev1.Secret) (int, error) {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return 0, err
	}
	res := cli.Put().
		Namespace(secret.GetNamespace()).
		Resource("secrets").
		Name(secret.Name).
		Body(secret).
		Do(ctx)
	return decodeInto(res, secret)
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
