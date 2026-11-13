//go:build integration
// +build integration

// Package crdvalidation proves, against a real apiserver, that the CRDs refuse
// what their schemas say they refuse: CEL rules and list bounds aren't
// evaluated anywhere else.
package crdvalidation

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/plumbing/e2e"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/support/kind"
)

var testenv env.Environment

const namespace = "crd-validation"

func TestMain(m *testing.M) {
	// First, before any cluster exists: kind must never touch the developer's
	// kubeconfig, and this suite destroys its cluster at the end.
	restore := e2e.PinKubeconfig("authn-crd-validation")
	// A name only this suite uses: it destroys the cluster at the end.
	const clusterName = "authn-crd-validation-test"
	testenv = env.New()
	testenv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), clusterName),
		envfuncs.SetupCRDs("../../crds", "serviceaccount.authn.krateo.io_serviceaccounts.yaml"),
		e2e.CreateNamespace(namespace),
	).Finish(
		envfuncs.DeleteNamespace(namespace),
		envfuncs.DestroyCluster(clusterName),
	)
	code := testenv.Run(m)
	restore() // not deferred: os.Exit does not run defers
	os.Exit(code)
}

var mappings = schema.GroupVersionResource{Group: "serviceaccount.authn.krateo.io", Version: "v1alpha1", Resource: "serviceaccounts"}

// mapping is a ServiceAccount mapping whose spec.delegation is delegation.
func mapping(name string, delegation map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "serviceaccount.authn.krateo.io/v1alpha1",
		"kind":       "ServiceAccount",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"serviceAccountRef": map[string]any{"name": "bridge", "namespace": namespace},
			"groups":            []any{"agents"},
			"delegation":        delegation,
		},
	}}
}

func strs(v ...string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// The issued token's audiences (spec.delegation.audiences) are a DNS-1123
// subdomain or an absolute https URI with no userinfo, query or fragment,
// the format audit records them in (authn#155); a subject-token source must
// name the OIDCConfig and at least one audience.
func TestServiceAccountDelegationValidation(t *testing.T) {
	f := features.New("ServiceAccount spec.delegation").
		Assess("audiences", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			dyn, err := dynamic.NewForConfig(cfg.Client().RESTConfig())
			require.NoError(t, err)
			client := dyn.Resource(mappings).Namespace(namespace)
			label63 := strings.Repeat("a", 63)
			// The CRD must accept exactly what audit records (audit's
			// ValidTokenAudience), so each case's expectation is audit's own
			// answer; anchors pin a few, so a validator change can't make the
			// test vacuous.
			anchors := map[string]bool{"agentiko": true, "https://cmp.krateo.dev/mcp": true,
				"Agentiko": false, "https://cmp.krateo.dev/%41": false, "https://user@cmp.krateo.dev": false}
			cases := []string{
				"agentiko", "agents.krateo.io", "a.b-c.d", "Agentiko", "agent_iko", "-agentiko", "agentiko-",
				strings.Repeat("a", 253), strings.Repeat("a", 254),
				"https://cmp.krateo.dev", "https://cmp.krateo.dev/", "https://cmp.krateo.dev/mcp", "https://cmp.krateo.dev/mcp/",
				"https://cmp.krateo.dev/a.b/c_d/~e-f", "https://cmp.krateo.dev:443/mcp", "https://cmp.krateo.dev:65535",
				"https://cmp.krateo.dev:65536", "https://cmp.krateo.dev:0", "https://cmp.krateo.dev:0443", "https://cmp.krateo.dev:",
				"https://CMP.krateo.dev/mcp", "https://cmp.krateo.dev//mcp", "https://cmp.krateo.dev/./mcp", "https://cmp.krateo.dev/mcp/..",
				"https://cmp.krateo.dev/.hidden", "https://cmp.krateo.dev/%41", "https://cmp.krateo.dev/a;b", "https://user@cmp.krateo.dev",
				"https://cmp.krateo.dev/mcp?x=1", "https://cmp.krateo.dev/mcp#frag", "http://cmp.krateo.dev/mcp", "https://",
				"https://cmp.krateo.dev/m\tcp", "https://cmp.krateo.dev/mcp\u00e9", "https://[::1]/mcp", "https://1.2.3.4/mcp",
				"https://" + label63 + ".dev", "https://" + label63 + "a.dev",
				"https://" + strings.Repeat(label63+".", 4) + "dev",
				"https://cmp.krateo.dev/" + strings.Repeat("a", 2048-len("https://cmp.krateo.dev/")),
				"https://cmp.krateo.dev/" + strings.Repeat("a", 2049-len("https://cmp.krateo.dev/")),
			}
			for v, want := range anchors {
				require.Equal(t, want, audit.ValidTokenAudience(v), "anchor %q", v)
			}
			for i, v := range cases {
				want := audit.ValidTokenAudience(v)
				obj := mapping(fmt.Sprintf("aud-%d", i), map[string]any{"allowed": true, "audiences": strs(v)})
				_, err := client.Create(ctx, obj, metav1.CreateOptions{})
				if want {
					require.NoError(t, err, "%q: audit records it, so the CRD must accept it", v)
					continue
				}
				require.Error(t, err, "%q: audit refuses it, so the CRD must too", v)
				if len(v) <= 2048 {
					require.Contains(t, err.Error(), "token_audience", "%q: refused by the format rule", v)
				}
			}
			return ctx
		}).
		Assess("subject-token sources", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			dyn, err := dynamic.NewForConfig(cfg.Client().RESTConfig())
			require.NoError(t, err)
			client := dyn.Resource(mappings).Namespace(namespace)
			ok := map[string]any{"allowed": true, "audiences": strs("agentiko"),
				"subjectTokens": []any{map[string]any{"oidcConfig": "keycloak", "audiences": strs("https://cmp.krateo.dev/mcp")}}}
			_, err = client.Create(ctx, mapping("st-ok", ok), metav1.CreateOptions{})
			require.NoError(t, err)

			for name, src := range map[string]map[string]any{
				"st-no-audience":     {"oidcConfig": "keycloak"},
				"st-empty-audiences": {"oidcConfig": "keycloak", "audiences": []any{}},
				"st-no-config":       {"audiences": strs("https://cmp.krateo.dev/mcp")},
			} {
				_, err := client.Create(ctx, mapping(name, map[string]any{"allowed": true, "subjectTokens": []any{src}}), metav1.CreateOptions{})
				require.Error(t, err, "%s must be refused", name)
			}
			dup := map[string]any{"allowed": true, "subjectTokens": []any{
				map[string]any{"oidcConfig": "keycloak", "audiences": strs("a")},
				map[string]any{"oidcConfig": "keycloak", "audiences": strs("b")},
			}}
			_, err = client.Create(ctx, mapping("st-dup", dup), metav1.CreateOptions{})
			require.Error(t, err, "one entry per OIDCConfig")
			return ctx
		}).Feature()
	testenv.Test(t, f)
}
