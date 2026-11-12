package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helmForTest is the helm binary for a chart test. Without helm the test is
// skipped, unless AUTHN_REQUIRE_HELM is set, as the chart-tests workflow sets
// it: there a missing helm is a failure, so a chart test can't pass by not
// running.
func helmForTest(t *testing.T) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("AUTHN_REQUIRE_HELM") != "" {
			t.Fatalf("AUTHN_REQUIRE_HELM is set but helm isn't installed: %v", err)
		}
		t.Skip("helm isn't installed; set AUTHN_REQUIRE_HELM to make this fail instead")
	}
	return helm
}

// renderChart renders helm/authn with the given --set flags, its Chart.yaml
// placeholders filled as the release workflow fills them.
func renderChart(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	helm := helmForTest(t)
	src := filepath.Join("..", "..", "helm", "authn")
	dst := filepath.Join(t.TempDir(), "authn")
	require.NoError(t, filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if rel == "Chart.yaml" {
			b = []byte(strings.NewReplacer("CHART_VERSION", "0.0.0", "APP_VERSION", "0.0.0").Replace(string(b)))
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	}))
	args := []string{"template", "authn", dst}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command(helm, args...).CombinedOutput()
	return string(out), err
}

// networkPolicy is the rendered internal NetworkPolicy document, "" when
// there is none.
func networkPolicy(rendered string) string {
	for _, doc := range strings.Split(rendered, "\n---\n") {
		if strings.Contains(doc, "kind: NetworkPolicy") {
			return doc
		}
	}
	return ""
}

// By default authn's pods admit anyone on the public port and only
// identity-lifecycle's controller on the internal one; the policy can be
// turned off and its peers replaced, and an empty peer list, which would
// admit everyone, refuses to render.
func TestChartInternalNetworkPolicy(t *testing.T) {
	out, err := renderChart(t)
	require.NoError(t, err, out)
	np := networkPolicy(out)
	require.NotEmpty(t, np, "on by default")
	assert.Contains(t, np, "policyTypes:\n    - Ingress")
	// The public port: a rule with no `from`, open as without a policy.
	assert.Contains(t, np, "- ports:\n        - port: http\n          protocol: TCP\n    - ports:")
	// The internal port: only the listed peer.
	internal := np[strings.Index(np, "port: internal"):]
	assert.Contains(t, internal, "from:")
	assert.Regexp(t, `(?m)app\.kubernetes\.io/name: identity-lifecycle$`, internal)
	assert.Contains(t, internal, "app.kubernetes.io/instance: identity-lifecycle")
	assert.NotContains(t, internal, "identity-lifecycle-intake", "the public intake is never a peer")

	out, err = renderChart(t, "internal.networkPolicy.enabled=false")
	require.NoError(t, err, out)
	assert.Empty(t, networkPolicy(out), "off: no policy")

	out, err = renderChart(t, "internal.networkPolicy.from[0].namespaceSelector.matchLabels.team=idl")
	require.NoError(t, err, out)
	assert.Contains(t, networkPolicy(out), "team: idl", "the peers are configurable")

	for _, empty := range []string{"internal.networkPolicy.from=null", "internal.networkPolicy.from={}"} {
		out, err = renderChart(t, empty)
		assert.Error(t, err, "an empty peer list must not render (%s):\n%s", empty, out)
	}
}
