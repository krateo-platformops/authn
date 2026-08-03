package restaction

import (
	"context"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/client"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"

	snowplowapis "github.com/krateo-platformops/snowplow/apis"
	snowplow "github.com/krateo-platformops/snowplow/apis/templates/v1"
)

// Add this to your client package
func newWithScheme(config *rest.Config, gv schema.GroupVersion, scheme *runtime.Scheme) (*rest.RESTClient, error) {
	// Clone your existing New function but add scheme support
	config = rest.CopyConfig(config)
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = serializer.NewCodecFactory(scheme)
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	return rest.RESTClientFor(config)
}

func Get(ctx context.Context, rc *rest.Config, ref *core.ObjectRef) (*snowplow.RESTAction, error) {
	cli, err := client.New(rc, schema.GroupVersion{Group: "templates.krateo.io", Version: "v1"})
	if err != nil {
		return nil, err
	}

	res := &snowplow.RESTAction{}
	err = cli.Get().
		Resource("restactions").
		Namespace(ref.Namespace).Name(ref.Name).
		Do(ctx).
		Into(res)

	return res, err
}

func CreateOrUpdate(ctx context.Context, rc *rest.Config, restaction *snowplow.RESTAction) error {
	scheme := runtime.NewScheme()
	snowplowapis.AddToScheme(scheme)
	cli, err := newWithScheme(rc, schema.GroupVersion{Group: "templates.krateo.io", Version: "v1"}, scheme)
	if err != nil {
		return err
	}

	// First try to get the resource
	existingObj := &snowplow.RESTAction{}
	err = cli.Get().
		Namespace(restaction.GetNamespace()).
		Resource("restactions").
		Name(restaction.GetName()).
		Do(ctx).
		Into(existingObj)

	if err != nil {
		if apierrors.IsNotFound(err) {
			// Resource doesn't exist, create it
			return cli.Post().
				Namespace(restaction.GetNamespace()).
				Resource("restactions").
				Body(restaction).
				Do(ctx).
				Error()
		}
		return err // Return any other error
	}

	restaction.ResourceVersion = existingObj.ResourceVersion
	// Resource exists, update it
	return cli.Put().
		Namespace(restaction.GetNamespace()).
		Resource("restactions").
		Name(restaction.GetName()).
		Body(restaction).
		Do(ctx).
		Error()
}

func Update(ctx context.Context, rc *rest.Config, restaction *snowplow.RESTAction) error {
	cli, err := client.New(rc, schema.GroupVersion{Group: "templates.krateo.io", Version: "v1"})
	if err != nil {
		return err
	}
	return cli.Put().
		Namespace(restaction.GetNamespace()).
		Resource("restactions").
		Name(restaction.Name).
		Body(restaction).
		Do(ctx).
		Error()
}

func Delete(ctx context.Context, rc *rest.Config, ref *core.ObjectRef) error {
	cli, err := client.New(rc, schema.GroupVersion{Group: "templates.krateo.io", Version: "v1"})
	if err != nil {
		return err
	}

	return cli.Delete().
		Namespace(ref.Namespace).
		Resource("restactions").
		Name(ref.Name).
		Do(ctx).
		Error()
}
