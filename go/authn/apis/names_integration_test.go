//go:build integration
// +build integration

package apis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	basicv1alpha1 "github.com/krateo-platformops/authn/apis/authn/basic/v1alpha1"
	serviceaccountv1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"

	"github.com/krateo-platformops/plumbing/e2e"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/support/kind"
)

// The name rule against a real apiserver (#140): the Kubernetes version both
// shared clusters run, so what CEL admits and refuses here is what they do.
const nodeImage = "kindest/node:v1.36.4"

var (
	testenv   env.Environment
	namespace = "authn-crdnames"
)

func TestMain(m *testing.M) {
	// First, before any cluster exists: kind must never touch the developer's
	// kubeconfig.
	restore := e2e.PinKubeconfig("authn-crdnames")
	// A name only this suite uses: it destroys the cluster at the end.
	clusterName := "authn-crdnames-test"
	testenv = env.New()
	testenv.Setup(
		envfuncs.CreateClusterWithOpts(kind.NewProvider(), clusterName, kind.WithImage(nodeImage)),
		e2e.CreateNamespace(namespace),
	).Finish(
		envfuncs.DestroyCluster(clusterName),
	)
	code := testenv.Run(m)
	restore() // not deferred: os.Exit does not run defers
	os.Exit(code)
}

var crdGVR = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

type kindUnderTest struct {
	crdFile string
	gvr     schema.GroupVersionResource
	kind    string
	spec    map[string]any
}

func TestNameRuleUser(t *testing.T) {
	testNameRule(t, kindUnderTest{
		crdFile: "basic.authn.krateo.io_users.yaml",
		gvr:     basicv1alpha1.SchemeGroupVersion.WithResource("users"),
		kind:    basicv1alpha1.UserKind,
		spec: map[string]any{
			"displayName": "Alice",
			"avatarURL":   "",
			"passwordRef": map[string]any{"name": "alice-password", "namespace": namespace, "key": "password"},
		},
	})
}

func TestNameRuleServiceAccount(t *testing.T) {
	testNameRule(t, kindUnderTest{
		crdFile: "serviceaccount.authn.krateo.io_serviceaccounts.yaml",
		gvr:     serviceaccountv1alpha1.SchemeGroupVersion.WithResource("serviceaccounts"),
		kind:    "ServiceAccount",
		spec: map[string]any{
			"displayName":       "Agent",
			"serviceAccountRef": map[string]any{"name": "agent", "namespace": namespace},
		},
	})
}

// An object created before the rule existed stays updatable and deletable once
// it does; a new name the transform would rewrite is refused however it is
// created; a well-formed one is admitted.
func testNameRule(t *testing.T, k kindUnderTest) {
	f := features.New(k.kind).
		Assess("existing names are kept, new ones are checked at create", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			dyn, err := dynamic.NewForConfig(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatal(err)
			}
			if dc, err := discovery.NewDiscoveryClientForConfig(cfg.Client().RESTConfig()); err == nil {
				if v, err := dc.ServerVersion(); err == nil {
					t.Logf("apiserver %s (%s)", v.GitVersion, nodeImage)
				}
			}
			withRule := loadCRD(t, filepath.Join("..", "crds", k.crdFile))
			withoutRule := withRule.DeepCopy()
			root := []string{"spec", "versions"}
			versions, _, _ := unstructured.NestedSlice(withoutRule.Object, root...)
			if len(versions) != 1 {
				t.Fatalf("%s: %d versions, want 1", k.crdFile, len(versions))
			}
			oas := versions[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
			if _, ok := oas["x-kubernetes-validations"]; !ok {
				t.Fatalf("%s carries no root rule", k.crdFile)
			}
			delete(oas, "x-kubernetes-validations")
			if err := unstructured.SetNestedSlice(withoutRule.Object, versions, root...); err != nil {
				t.Fatal(err)
			}

			crds := dyn.Resource(crdGVR)
			objs := dyn.Resource(k.gvr).Namespace(namespace)

			// 1. The CRD as it was before #140, and an object whose name
			//    the transform rewrites.
			if _, err := crds.Create(ctx, withoutRule, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			waitEstablished(ctx, t, dyn, withRule.GetName())
			const existing = "alice.smith"
			waitFor(ctx, t, "the CRD serves creates", func() (bool, error) {
				_, err := objs.Create(ctx, k.object(existing), metav1.CreateOptions{})
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return err == nil, err
			})
			t.Logf("without the rule: created %s %q", k.kind, existing)

			// 2. The CRD with the rule.
			cur, err := crds.Get(ctx, withRule.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			withRule.SetResourceVersion(cur.GetResourceVersion())
			if _, err := crds.Update(ctx, withRule, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			waitFor(ctx, t, "the rule is in force", func() (bool, error) {
				_, err := objs.Create(ctx, k.object("probe.dotted"), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				return refusedByRule(err), nil
			})
			t.Logf("with the rule: a dry-run create of %q is refused", "probe.dotted")

			// 3. The existing object stays updatable and deletable.
			merge := func(what, patch string) {
				t.Helper()
				if _, err := objs.Patch(ctx, existing, types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
					t.Fatalf("%s of existing %q: %v", what, existing, err)
				}
				t.Logf("accepted: %s of existing %q", what, existing)
			}
			merge("spec patch", `{"spec":{"displayName":"Changed"}}`)
			merge("label", `{"metadata":{"labels":{"team":"a"}}}`)
			merge("finalizer add", `{"metadata":{"finalizers":["example.com/hold"]}}`)
			if _, err := objs.Patch(ctx, existing, types.JSONPatchType,
				[]byte(`[{"op":"remove","path":"/metadata/finalizers"}]`), metav1.PatchOptions{}); err != nil {
				t.Fatalf("finalizer remove of existing %q: %v", existing, err)
			}
			t.Logf("accepted: finalizer remove of existing %q", existing)
			got, err := objs.Get(ctx, existing, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if dn, _, _ := unstructured.NestedString(got.Object, "spec", "displayName"); dn != "Changed" || got.GetLabels()["team"] != "a" || len(got.GetFinalizers()) != 0 {
				t.Fatalf("existing %q after the updates: displayName %q, labels %v, finalizers %v", existing, dn, got.GetLabels(), got.GetFinalizers())
			}
			if err := objs.Delete(ctx, existing, metav1.DeleteOptions{}); err != nil {
				t.Fatalf("delete of existing %q: %v", existing, err)
			}
			waitFor(ctx, t, "the existing object is gone", func() (bool, error) {
				_, err := objs.Get(ctx, existing, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				return false, err
			})
			t.Logf("accepted: delete of existing %q", existing)

			// 4. New names the transform rewrites are refused, with the
			//    message, however they are created.
			for _, name := range []string{"bob.jones", strings.Repeat("a", 64)} {
				_, err := objs.Create(ctx, k.object(name), metav1.CreateOptions{})
				if !refusedByRule(err) {
					t.Fatalf("create of %q: %v, want the rule's refusal", name, err)
				}
				t.Logf("refused: create of %q: %v", name, err)
			}
			const applied = "carol.x"
			body, err := json.Marshal(k.object(applied).Object)
			if err != nil {
				t.Fatal(err)
			}
			force := true
			_, err = objs.Patch(ctx, applied, types.ApplyPatchType, body,
				metav1.PatchOptions{FieldManager: "authn-crdnames-test", Force: &force})
			if !refusedByRule(err) {
				t.Fatalf("server-side apply of %q: %v, want the rule's refusal", applied, err)
			}
			t.Logf("refused: server-side apply of %q: %v", applied, err)

			// 5. A well-formed name is admitted, and stays updatable.
			const good = "bob"
			if _, err := objs.Create(ctx, k.object(good), metav1.CreateOptions{}); err != nil {
				t.Fatalf("create of %q: %v", good, err)
			}
			if _, err := objs.Patch(ctx, good, types.MergePatchType, []byte(`{"spec":{"displayName":"Bob"}}`), metav1.PatchOptions{}); err != nil {
				t.Fatalf("spec patch of %q: %v", good, err)
			}
			t.Logf("accepted: create and spec patch of %q", good)

			if err := crds.Delete(ctx, withRule.GetName(), metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			return ctx
		}).Feature()

	testenv.Test(t, f)
}

func (k kindUnderTest) object(name string) *unstructured.Unstructured {
	spec, _ := json.Marshal(k.spec)
	var copied map[string]any
	_ = json.Unmarshal(spec, &copied)
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": k.gvr.GroupVersion().String(),
		"kind":       k.kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       copied,
	}}
}

func refusedByRule(err error) bool {
	return apierrors.IsInvalid(err) && strings.Contains(err.Error(), nameMessage)
}

func loadCRD(t *testing.T, path string) *unstructured.Unstructured {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	js, err := yaml.ToJSON(raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(js); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return u
}

func waitEstablished(ctx context.Context, t *testing.T, dyn dynamic.Interface, name string) {
	t.Helper()
	waitFor(ctx, t, "CRD "+name+" is Established", func() (bool, error) {
		crd, err := dyn.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		conds, _, _ := unstructured.NestedSlice(crd.Object, "status", "conditions")
		for _, c := range conds {
			m, _ := c.(map[string]any)
			if m["type"] == "Established" && m["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	})
}

func waitFor(ctx context.Context, t *testing.T, what string, cond func() (bool, error)) {
	t.Helper()
	err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, time.Minute, true,
		func(context.Context) (bool, error) { return cond() })
	if err != nil {
		t.Fatalf("waiting until %s: %v", what, err)
	}
}
