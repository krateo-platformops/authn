package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// docOfKind is the rendered document of the given kind and name, "" when
// there is none.
func docOfKind(rendered, kind, name string) string {
	for _, doc := range strings.Split(rendered, "\n---\n") {
		if strings.Contains(doc, "kind: "+kind+"\n") && strings.Contains(doc, "name: "+name+"\n") {
			return doc
		}
	}
	return ""
}

// The internal listener's TLS (authn#145): off by default, with nothing
// rendered for it. With an issuerRef the chart requests a cert-manager
// Certificate for the internal Service's names, mounts its Secret, and points
// authn at the files; an issuerRef whose kind isn't Issuer or ClusterIssuer
// refuses to render.
func TestChartInternalTLS(t *testing.T) {
	out, err := renderChart(t)
	require.NoError(t, err, out)
	assert.NotContains(t, out, "kind: Certificate", "TLS is off by default")
	assert.NotContains(t, out, "AUTHN_INTERNAL_TLS_CERT_FILE")
	assert.NotContains(t, out, "internal-tls")

	out, err = renderChart(t, "internal.tls.issuerRef.kind=ClusterIssuer", "internal.tls.issuerRef.name=krateo-platform-ca")
	require.NoError(t, err, out)
	cert := docOfKind(out, "Certificate", "authn-internal")
	require.NotEmpty(t, cert, out)
	for _, want := range []string{
		"secretName: authn-internal-tls",
		"- authn-internal\n",
		"- authn-internal.default\n",
		"- authn-internal.default.svc\n",
		"- authn-internal.default.svc.cluster.local\n",
		"- server auth",
		"rotationPolicy: Always",
		"kind: ClusterIssuer",
		"name: krateo-platform-ca",
		"group: cert-manager.io",
	} {
		assert.Contains(t, cert, want)
	}

	cm := docOfKind(out, "ConfigMap", "authn")
	require.NotEmpty(t, cm, out)
	assert.Contains(t, cm, "AUTHN_INTERNAL_TLS_CERT_FILE: /etc/authn/internal-tls/tls.crt")
	assert.Contains(t, cm, "AUTHN_INTERNAL_TLS_KEY_FILE: /etc/authn/internal-tls/tls.key")

	dep := docOfKind(out, "Deployment", "authn")
	require.NotEmpty(t, dep, out)
	assert.Contains(t, dep, "mountPath: /etc/authn/internal-tls")
	assert.Contains(t, dep, "secretName: authn-internal-tls")

	_, err = renderChart(t, "internal.tls.issuerRef.kind=Certificate", "internal.tls.issuerRef.name=x")
	assert.Error(t, err, "a kind that isn't an issuer")
	out, err = renderChart(t, "internal.tls.issuerRef.name=krateo-platform-ca")
	require.Error(t, err, "a name without a kind")
	assert.Contains(t, out, "must be Issuer or ClusterIssuer")
}
