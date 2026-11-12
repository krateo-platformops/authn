package main

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
)

// The chart renders exactUsernames.enabled into the ConfigMap as the variable
// main reads (storage.EnvExactUsernames), "false" by default and "true" when
// turned on (authn#140). It needs helm, and is skipped without it; lint.yaml
// renders the chart's defaults in CI either way.
func TestChartRendersTheExactUsernamesFlag(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed")
	}
	chart := copyChart(t, filepath.Join("..", "..", "helm", "authn"))
	for _, tc := range []struct {
		name string
		set  []string
		want string
	}{
		{"default", nil, `"false"`},
		{"off", []string{"--set", "exactUsernames.enabled=false"}, `"false"`},
		{"on", []string{"--set", "exactUsernames.enabled=true"}, `"true"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"template", "smoke", chart, "--show-only", "templates/configmap.yaml"}, tc.set...)
			out, err := exec.Command(helm, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			line := storage.EnvExactUsernames + ": " + tc.want
			if !bytes.Contains(out, []byte(line)) {
				t.Errorf("the ConfigMap doesn't carry %s:\n%s", line, out)
			}
		})
	}
	// Setting the variable through env.* too would render the key twice: the
	// chart refuses, saying which value to set.
	for _, v := range []string{"true", "false"} {
		out, err := exec.Command(helm, "template", "smoke", chart, "--set-string", "env.AUTHN_EXACT_USERNAMES="+v).CombinedOutput()
		if err == nil {
			t.Errorf("env.AUTHN_EXACT_USERNAMES=%s rendered:\n%s", v, out)
		} else if !strings.Contains(string(out), "set exactUsernames.enabled instead") {
			t.Errorf("env.AUTHN_EXACT_USERNAMES=%s failed without saying why:\n%s", v, out)
		}
	}
	// The schema takes a boolean only: a string would render as one the
	// service parses differently.
	out, err := exec.Command(helm, "template", "smoke", chart, "--set", "exactUsernames.enabled=yes").CombinedOutput()
	if err == nil {
		t.Errorf("the schema accepted a string for exactUsernames.enabled:\n%s", out)
	}
}

// copyChart copies the chart to a temporary directory with its release
// placeholders replaced, as lint.yaml does before rendering it.
func copyChart(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "authn")
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if rel == "Chart.yaml" {
			b = []byte(strings.NewReplacer("CHART_VERSION", "0.0.0", "APP_VERSION", "0.0.0").Replace(string(b)))
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}
