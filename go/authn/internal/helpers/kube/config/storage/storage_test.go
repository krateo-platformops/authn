//go:build integration
// +build integration

package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
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
	// First, before any cluster exists: kind must never touch the developer's
	// kubeconfig, and this suite destroys its cluster at the end.
	restore := e2e.PinKubeconfig("authn-storage")
	namespace = "demo-system"
	// A name only this suite uses: it destroys the cluster at the end, so a
	// common name (it was "krateo") deletes whatever cluster a developer has
	// by that name.
	clusterName = "authn-storage-test"
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

	code := testenv.Run(m)
	restore() // not deferred: os.Exit does not run defers
	os.Exit(code)
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
				Strategy: StrategyBasic,
				CertData: identityCert(t, username, []string{"devs"}),
				KeyData:  "YYY",
				CAData:   "ZZZ",
				Server:   "AAA",
				ProxyURL: "BBB",
			}

			store := Default(cfg.Client().RESTConfig())

			// Twice: the first Put creates the Secret, the second finds it and
			// updates it.
			for i, verb := range []string{"create", "update"} {
				w, err := store.Put(username, want)
				if err != nil {
					t.Fatal(err)
				}
				// What Put reports is what the audit record names (AUDIT-4).
				if w.Verb != verb || w.UID == "" || w.StatusCode == 0 {
					t.Fatalf("Put #%d reported %+v, want verb %q with a uid and a status", i+1, w, verb)
				}
			}

			// Read back from the apiserver, as every consumer does: authn never
			// reads a credential back itself.
			sec, err := secrets.Get(ctx, cfg.Client().RESTConfig(),
				&core.SecretKeySelector{Name: ClientConfigSecretName(username), Namespace: namespace})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for k, v := range sec.Data {
				got[k] = string(v)
			}
			wantData := map[string]string{
				CALabel:         want.CAData,
				ClientCertLabel: want.CertData,
				ClientKeyLabel:  want.KeyData,
				ServerUrlLabel:  want.Server,
				ProxyUrlLabel:   want.ProxyURL,
			}
			if diff := cmp.Diff(wantData, got); len(diff) > 0 {
				t.Fatal(diff)
			}
			if s := sec.Annotations[StrategyAnnotation]; s != string(StrategyBasic) {
				t.Fatalf("strategy annotation %q, want %q", s, StrategyBasic)
			}

			return ctx
		}).Feature()

	testenv.Test(t, f)
}
