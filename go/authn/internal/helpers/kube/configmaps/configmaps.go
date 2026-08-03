package configmaps

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/client"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

func Get(ctx context.Context, rc *rest.Config, sel *core.SecretKeySelector) (*corev1.ConfigMap, error) {
	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return nil, err
	}

	res := &corev1.ConfigMap{}
	err = cli.Get().
		Resource("configmaps").
		Namespace(sel.Namespace).Name(sel.Name).
		Do(ctx).
		Into(res)

	return res, err
}

func CACrt(ctx context.Context, rc *rest.Config) (string, error) {
	const (
		name = "kube-root-ca.crt"
	)

	namespace, err := util.GetOperatorNamespace()
	if err != nil {
		return "", err
	}

	cli, err := client.New(rc, schema.GroupVersion{Group: "", Version: "v1"})
	if err != nil {
		return "", err
	}

	res := &corev1.ConfigMap{}
	err = cli.Get().
		Resource("configmaps").
		Namespace(namespace).Name(name).
		Do(ctx).
		Into(res)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("configmaps '%s' not found (namespace: %s)", name, namespace)
		}
		return "", err
	}

	crt, ok := res.Data["ca.crt"]
	if !ok {
		return "", fmt.Errorf("ca.crt key not found in configmaps '%s' (namespace: %s)", name, namespace)
	}

	enc := base64.StdEncoding.EncodeToString([]byte(crt))
	return enc, err
}
