//go:build integration
// +build integration

package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"

	"github.com/krateo-platformops/plumbing/e2e"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/support/kind"
)

var (
	testenv     env.Environment
	clusterName string
	namespace   string
)

func TestMain(m *testing.M) {
	namespace = "demo-system"
	clusterName = "krateo"
	testenv = env.New()

	testenv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), clusterName),
		e2e.CreateNamespace(namespace),

		func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			// TODO: add a wait.For conditional helper that can
			// check and wait for the existence of a CRD resource
			time.Sleep(2 * time.Second)
			return ctx, nil
		},
	).Finish(
		envfuncs.DeleteNamespace(namespace),
		envfuncs.DestroyCluster(clusterName),
	)

	os.Exit(testenv.Run(m))
}

func TestStorage(t *testing.T) {
	f := features.New("Setup").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			os.Setenv(util.NamespaceEnvVar, namespace)
			return ctx
		}).
		Assess("Default Store", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			const (
				username = "Pinco.Pallo@kubeworld.it"
			)

			want := &AuthInfo{
				CertData: "XXX",
				KeyData:  "YYY",
				CAData:   "ZZZ",
				Server:   "AAA",
				ProxyURL: "BBB",
			}

			store := Default(cfg.Client().RESTConfig())

			err := store.Put(username, want)
			if err != nil {
				t.Fatal(err)
			}

			got, err := store.Get(username)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(got, want); len(diff) > 0 {
				t.Fatal(diff)
			}

			return ctx
		}).Feature()

	testenv.Test(t, f)
}
