package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The ServiceAccount the pod runs as is the one its RoleBinding and
// ClusterRoleBinding name, whatever serviceAccount says: a binding naming
// another one leaves authn without CSR approval and TokenReview, a 403 on the
// call rather than anything in a condition. With create false a name is
// required: the chart won't bind authn's rights to the namespace's default
// ServiceAccount.
func TestChartServiceAccountIsTheBoundOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sets    []string
		sa      string
		created bool
	}{
		{name: "shipped values", sa: "authn", created: true},
		{name: "named and created", sets: []string{"serviceAccount.name=authn-target"}, sa: "authn-target", created: true},
		{name: "existing, not created", sets: []string{"serviceAccount.create=false", "serviceAccount.name=preexisting"}, sa: "preexisting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderChart(t, tc.sets...)
			require.NoError(t, err, out)

			deploy := topLevelDoc(out, "Deployment", "authn")
			require.NotEmpty(t, deploy, out)
			assert.Contains(t, deploy, "serviceAccountName: "+tc.sa+"\n")

			sa := topLevelDoc(out, "ServiceAccount", tc.sa)
			if tc.created {
				assert.NotEmpty(t, sa, "the chart creates the ServiceAccount the pod runs as")
			} else {
				assert.Empty(t, sa, "with create false the chart renders no ServiceAccount")
				assert.NotContains(t, out, "\nkind: ServiceAccount\n")
			}

			subject := "- kind: ServiceAccount\n  name: " + tc.sa + "\n  namespace: default\n"
			for _, kind := range []string{"RoleBinding", "ClusterRoleBinding"} {
				binding := topLevelDoc(out, kind, "authn-default")
				require.NotEmpty(t, binding, "%s authn-default\n%s", kind, out)
				assert.Contains(t, binding, subject, kind)
				assert.Equal(t, 1, strings.Count(binding, "- kind: ServiceAccount"), kind)
			}
		})
	}

	// The values schema refuses it first, so a schema reader (installer's
	// componentValues) sees the rule. An empty name is refused the same way.
	for _, sets := range [][]string{{"serviceAccount.create=false"}, {"serviceAccount.create=false", "serviceAccount.name="}} {
		out, err := renderChart(t, sets...)
		require.Error(t, err, out)
		assert.Contains(t, out, "values don't meet the specifications of the schema", sets)
		assert.Contains(t, out, "serviceAccount", sets)
		assert.NotContains(t, out, "name: default\n")
	}

	// Without the schema, the template still refuses.
	out, err := renderChartWith(t, []string{"--skip-schema-validation"}, "serviceAccount.create=false")
	require.Error(t, err, out)
	assert.Contains(t, out, "serviceAccount.name is required when serviceAccount.create is false")
	assert.NotContains(t, out, "name: default\n")
}

// topLevelDoc is the rendered document whose own kind and metadata.name are
// the given ones, newline-terminated; "" when there is none. Unlike
// docOfKind it doesn't match a binding by its subject's kind and name.
func topLevelDoc(rendered, kind, name string) string {
	for _, doc := range strings.Split(rendered, "\n---\n") {
		doc = strings.TrimRight(doc, "\n") + "\n"
		if strings.Contains(doc, "\nkind: "+kind+"\nmetadata:\n  name: "+name+"\n") {
			return doc
		}
	}
	return ""
}
