package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The LDAP login's TLS (authn#160) verifies the server for the host in
// spec.dialURL, against the given roots or the system ones, and never skips
// verification. A dialURL without a host can't be verified and is refused.
func TestVerifyingTLSConfig(t *testing.T) {
	cfg, err := verifyingTLSConfig("ldap://ldap.corp.example:389", nil)
	require.NoError(t, err)
	assert.Equal(t, "ldap.corp.example", cfg.ServerName, "the host, without the port")
	assert.False(t, cfg.InsecureSkipVerify)
	assert.Nil(t, cfg.RootCAs, "nil: the system roots")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)

	roots := x509.NewCertPool()
	cfg, err = verifyingTLSConfig("ldaps://10.0.0.7:636", roots)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.7", cfg.ServerName)
	assert.Same(t, roots, cfg.RootCAs)

	_, err = verifyingTLSConfig("ldap:///dc=example", nil)
	assert.Error(t, err, "no host to verify")
	_, err = verifyingTLSConfig("://nope", nil)
	assert.Error(t, err, "not a URL")
}

// Against a real TLS server, the config refuses a certificate the roots don't
// verify, and one for another host, and accepts the server once its CA is
// trusted: what InsecureSkipVerify used to accept unconditionally.
func TestVerifyingTLSConfigVerifiesTheServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // a certificate for example.com and 127.0.0.1
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	trusted := x509.NewCertPool()
	trusted.AddCert(srv.Certificate())

	handshake := func(dialURL string, roots *x509.CertPool) error {
		cfg, err := verifyingTLSConfig(dialURL, roots)
		require.NoError(t, err)
		conn, err := tls.Dial("tcp", addr, cfg)
		if err == nil {
			_ = conn.Close()
		}
		return err
	}
	assert.Error(t, handshake("ldaps://127.0.0.1:"+port, nil), "a CA the system roots don't hold")
	assert.Error(t, handshake("ldaps://ldap.wrong.example:"+port, trusted), "a certificate for another host")
	assert.NoError(t, handshake("ldaps://127.0.0.1:"+port, trusted), "the trusted CA, the right host")
	assert.NoError(t, handshake("ldap://example.com:"+port, trusted), "StartTLS's ldap:// URL names the host the same way")
}

// tlsCAServer serves the LDAPConfig "corp" with spec.tlsCA naming the Secret
// ldap-ca's key ca.crt, holding caPEM; secretCode answers the Secret's read.
func tlsCAServer(t *testing.T, caPEM []byte, secretCode int) *rest.Config {
	t.Helper()
	t.Setenv("POD_NAMESPACE", "krateo-system")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/ldap.authn.krateo.io/v1alpha1/namespaces/krateo-system/ldapconfigs/corp":
			fmt.Fprint(w, `{"apiVersion":"ldap.authn.krateo.io/v1alpha1","kind":"LDAPConfig","metadata":{"name":"corp","namespace":"krateo-system"},
				"spec":{"dialURL":"ldap://ldap.corp.example:389","baseDN":"dc=example","tls":true,
				"tlsCA":{"name":"ldap-ca","namespace":"krateo-system","key":"ca.crt"}}}`)
		case "/api/v1/namespaces/krateo-system/secrets/ldap-ca":
			if secretCode != http.StatusOK {
				w.WriteHeader(secretCode)
				fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":%d}`, secretCode)
				return
			}
			fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"ldap-ca","namespace":"krateo-system"},"data":{"ca.crt":%q}}`,
				base64.StdEncoding.EncodeToString(caPEM))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// spec.tlsCA's certificates become the roots the server is verified against.
// A CA authn can't read is its failure (LDAPConfigLookupFailed); a key that
// holds no certificate is a misconfigured LDAPConfig (LDAPConfigInvalid).
// Both are found before any connection.
func TestGetConfigReadsTheTLSCA(t *testing.T) {
	ca := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ca.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate().Raw})

	cfg, err := getConfig(tlsCAServer(t, caPEM, http.StatusOK), "corp")
	require.NoError(t, err)
	require.NotNil(t, cfg.tlsConfig)
	assert.Equal(t, "ldap.corp.example", cfg.tlsConfig.ServerName)
	require.NotNil(t, cfg.tlsConfig.RootCAs, "the CA from spec.tlsCA, not the system roots")
	_, verr := ca.Certificate().Verify(x509.VerifyOptions{Roots: cfg.tlsConfig.RootCAs})
	assert.NoError(t, verr, "the configured CA is in the roots")

	_, err = getConfig(tlsCAServer(t, []byte("not a certificate"), http.StatusOK), "corp")
	require.Error(t, err)
	assert.Equal(t, CauseLDAPConfigInvalid, status.FromError(err).Details.Causes[0].Type)

	_, err = getConfig(tlsCAServer(t, caPEM, http.StatusForbidden), "corp")
	require.Error(t, err)
	assert.Equal(t, CauseLDAPConfigLookupFailed, status.FromError(err).Details.Causes[0].Type)
}

// The login hands the verifying config to the dial (ldaps://) and to StartTLS.
func TestLoginUsesTheVerifyingTLSConfig(t *testing.T) {
	want, err := verifyingTLSConfig("ldap://ldap.corp.example:389", nil)
	require.NoError(t, err)
	// The admin bind is refused, so the login stops right after the TLS
	// handshake this test is about.
	srvLDAP := &fakeLDAP{adminBind: ldapErr(ldap.LDAPResultInvalidCredentials)}
	var dialed *tls.Config
	orig := dial
	dial = func(_ string, c *tls.Config) (ldap.Client, error) { dialed = c; return srvLDAP, nil }
	t.Cleanup(func() { dial = orig })

	_, _ = doLogin("alice", "pw", ldapConfig{name: "corp", dialURL: "ldap://ldap.corp.example:389", tls: true,
		bindDN: adminDN, baseDN: "dc=example", tlsConfig: want})
	assert.Same(t, want, dialed, "the dial verifies an ldaps:// server")
	assert.Same(t, want, srvLDAP.tlsConfig, "StartTLS verifies the server")
	require.NotNil(t, srvLDAP.tlsConfig)
	assert.False(t, srvLDAP.tlsConfig.InsecureSkipVerify)
}

// The real dial verifies an ldaps:// server with the config it's given: the
// TLS handshake happens at dial time, before any LDAP exchange, so a TLS
// server that speaks no LDAP is enough to prove it. Trusted, the dial
// succeeds; with the system roots, the test CA isn't trusted and it fails.
func TestDialVerifiesAnLDAPSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	ldapsURL := "ldaps://" + strings.TrimPrefix(srv.URL, "https://")
	trusted := x509.NewCertPool()
	trusted.AddCert(srv.Certificate())

	cfg, err := verifyingTLSConfig(ldapsURL, trusted)
	require.NoError(t, err)
	c, err := dial(ldapsURL, cfg)
	require.NoError(t, err, "the configured CA verifies the server")
	_ = c.Close()

	cfg, err = verifyingTLSConfig(ldapsURL, nil)
	require.NoError(t, err)
	_, err = dial(ldapsURL, cfg)
	assert.Error(t, err, "the system roots don't trust the test CA")
}
