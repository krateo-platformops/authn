//go:build integration
// +build integration

package storage

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"

	"github.com/krateo-platformops/plumbing/e2e"
	"github.com/krateo-platformops/plumbing/endpoints"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		}).
		Assess("Exact Store (authn#140, authn#144)", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			rc := cfg.Client().RESTConfig()
			get := func(name string) *corev1.Secret {
				t.Helper()
				sec, err := secrets.Get(ctx, rc, &core.SecretKeySelector{Name: name, Namespace: namespace})
				if err != nil {
					t.Fatalf("reading %s: %v", name, err)
				}
				return sec
			}
			legacyOf := func(name, cn, claim string) *corev1.Secret {
				t.Helper()
				sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace,
					Annotations: map[string]string{StrategyAnnotation: "oidc", ClaimAnnotation: claim}},
					StringData: map[string]string{ClientCertLabel: identityCert(t, cn, []string{"devs"})}}
				if _, err := secrets.Create(ctx, rc, sec); err != nil {
					t.Fatalf("creating %s: %v", name, err)
				}
				return get(name)
			}
			store := NewStore(rc, Naming{Exact: true})
			nfo := func(cn, claim string) *AuthInfo {
				return &AuthInfo{Strategy: StrategyOIDC, Claim: claim, CertData: identityCert(t, cn, []string{"devs"}),
					KeyData: "k", CAData: "ca", Server: "s"}
			}

			// X/Y: johndoe's Secret exists; john.doe writes its own exact one,
			// twice (create, then update), and johndoe's is untouched.
			y := legacyOf("johndoe-clientconfig", "johndoe", `["oidc","kc","y"]`)
			for _, verb := range []string{"create", "update"} {
				w, err := store.Put("john.doe", nfo("john.doe", `["oidc","kc","x"]`))
				if err != nil {
					t.Fatal(err)
				}
				if w.Name != "john.doe-clientconfig" || w.Verb != verb || w.UID == "" {
					t.Fatalf("Put reported %+v, want john.doe-clientconfig, %s, with a uid", w, verb)
				}
			}
			x := get("john.doe-clientconfig")
			if x.Annotations[UsernameAnnotation] != "john.doe" || x.Labels[PrincipalLabel] != "human" ||
				x.Labels[UsernameLabelLabel] != "john-doe--30f69670bba2" {
				t.Fatalf("identity keys: annotations %v, labels %v", x.Annotations, x.Labels)
			}
			if got := get("johndoe-clientconfig"); got.ResourceVersion != y.ResourceVersion {
				t.Fatalf("johndoe's Secret was written: resourceVersion %s -> %s", y.ResourceVersion, got.ResourceVersion)
			}

			// jane.roe's legacy Secret (janeroe-clientconfig, CN jane.roe):
			// janeroe's exact name. janeroe is refused, and it is untouched.
			jane := legacyOf("janeroe-clientconfig", "jane.roe", `["oidc","kc","jane"]`)
			if _, err := store.Put("janeroe", nfo("janeroe", `["oidc","kc","jane"]`)); !errors.Is(err, ErrClaimedByAnother) {
				t.Fatalf("Put over another username's Secret: %v, want ErrClaimedByAnother", err)
			}
			if got := get("janeroe-clientconfig"); got.ResourceVersion != jane.ResourceVersion {
				t.Fatal("jane.roe's legacy Secret was written")
			}

			// A reader, against the apiserver: exact first, then legacy, the
			// first Secret the username owns. jane.roe has no exact Secret, so
			// its legacy one is found; janeroe owns neither name.
			read := func(username string) string {
				for _, name := range (Naming{Exact: true}).SessionNames(username) {
					sec, err := secrets.Get(ctx, rc, &core.SecretKeySelector{Name: name, Namespace: namespace})
					if apierrors.IsNotFound(err) {
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if endpoints.OwnsSecret(sec, username) {
						return sec.Name
					}
				}
				return ""
			}
			for username, want := range map[string]string{
				"john.doe": "john.doe-clientconfig",
				"johndoe":  "johndoe-clientconfig",
				"jane.roe": "janeroe-clientconfig",
				"janeroe":  "",
			} {
				if got := read(username); got != want {
					t.Errorf("reader for %s found %q, want %q", username, got, want)
				}
			}
			return ctx
		}).Feature()

	testenv.Test(t, f)
}
