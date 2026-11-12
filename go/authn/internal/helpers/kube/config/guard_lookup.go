package config

import (
	"context"
	"fmt"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// clusterLookup reads the name guard's facts from the cluster.
type clusterLookup struct {
	rc  *rest.Config
	cli kubernetes.Interface
}

// newClusterLookup builds the lookup authn uses in a cluster.
func newClusterLookup(rc *rest.Config) (*clusterLookup, error) {
	cli, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	return &clusterLookup{rc: rc, cli: cli}, nil
}

func (l *clusterLookup) SessionSecret(ctx context.Context, username string) (*corev1.Secret, error) {
	return l.Secret(ctx, storage.ClientConfigSecretName(username))
}

func (l *clusterLookup) Secret(ctx context.Context, name string) (*corev1.Secret, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}
	sec, err := l.cli.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	// The Secret is named after its user: the error's text names neither.
	return sec, kerr.Wrap("reading the credential Secret", err)
}

func (l *clusterLookup) Provisioned(_ context.Context, username string) (bool, error) {
	// The resolvers' errors name neither the object nor the user (kerr).
	_, err := resolvers.UserGet(l.rc, username)
	switch {
	case err == nil:
		return true, nil
	case !apierrors.IsNotFound(err):
		return false, err
	}
	_, err = resolvers.ServiceAccountMappingGet(l.rc, username)
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

func (l *clusterLookup) BoundAsUser(ctx context.Context, username string) (bool, error) {
	crbs, err := l.cli.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("listing ClusterRoleBindings: %w", err)
	}
	for i := range crbs.Items {
		if namesUser(crbs.Items[i].Subjects, username) {
			return true, nil
		}
	}
	rbs, err := l.cli.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("listing RoleBindings: %w", err)
	}
	for i := range rbs.Items {
		if namesUser(rbs.Items[i].Subjects, username) {
			return true, nil
		}
	}
	return false, nil
}

// namesUser reports whether subjects include the User username. The apiserver
// matches a User subject by name alone, whatever its apiGroup says.
func namesUser(subjects []rbacv1.Subject, username string) bool {
	for _, s := range subjects {
		if s.Kind == rbacv1.UserKind && s.Name == username {
			return true
		}
	}
	return false
}
