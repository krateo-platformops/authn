package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The authn-crds chart ships exactly the CRDs controller-gen generates into
// crds/. CI's drift guard checks crds/ against the Go types only, so a change
// regenerated there but not copied into the chart would ship the old schema,
// and the apiserver would prune the new fields silently.
func TestChartCRDsAreTheGeneratedOnes(t *testing.T) {
	generated, err := filepath.Glob("crds/*.yaml")
	if err != nil || len(generated) == 0 {
		t.Fatalf("no generated CRDs found (%v)", err)
	}
	chart := filepath.Join("..", "..", "helm", "authn-crds", "templates")
	shipped, err := filepath.Glob(filepath.Join(chart, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(shipped) != len(generated) {
		t.Errorf("the chart ships %d CRDs, controller-gen generates %d", len(shipped), len(generated))
	}
	for _, g := range generated {
		want, err := os.ReadFile(g)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(chart, filepath.Base(g)))
		if err != nil {
			t.Errorf("%s is generated but not in the chart: %v", filepath.Base(g), err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s in the chart differs from crds/: copy it after make generate", filepath.Base(g))
		}
	}
}
