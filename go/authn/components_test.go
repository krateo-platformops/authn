package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// newComponents gives every component that names or reads session Secrets
// main's naming: the renewer, the backfill and the login generator (whose
// refusal names john.doe's exact Secret with exact names on, its legacy one
// off). The other options keep what main passes.
func TestNewComponentsGiveEveryComponentTheNaming(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		naming storage.Naming
		secret string
	}{
		{storage.Naming{Exact: true}, "john.doe-clientconfig"},
		{storage.Naming{}, "johndoe-clientconfig"},
	} {
		c := newComponents(componentConfig{
			RestConfig: &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: []byte("ca")}},
			Naming:     tc.naming, Log: zerolog.Nop(),
			KubernetesURL: "https://k8s.example", ClusterName: "krateo", CertDuration: time.Hour,
			SelfUsername: "authn", StorageNamespace: "krateo-system",
			ServiceCertDuration: 2 * time.Hour, RenewalThreshold: 0.5,
		})
		assert.Equal(t, tc.naming, c.Renewer.Naming, "renewer, exact=%v", tc.naming.Exact)
		assert.Equal(t, tc.naming, c.Backfill.Naming, "backfill, exact=%v", tc.naming.Exact)

		// A system: group is refused before anything is read or minted; the
		// refusal names the Secret the generator would have written.
		u := userinfo.NewDefaultUser("john.doe", "1", []string{"system:masters"}, nil)
		u.Subject = userinfo.Subject{Issuer: "kc", ID: "x"}
		issued, err := c.Generator.Generate(storage.StrategyBasic, u)
		require.Error(t, err)
		assert.Equal(t, tc.secret, issued.Secret.Name, "generator, exact=%v", tc.naming.Exact)

		assert.Equal(t, "authn", c.Renewer.Username)
		assert.Equal(t, "krateo-system", c.Renewer.Namespace)
		assert.Equal(t, "ca", c.Renewer.CAData)
		assert.Equal(t, "https://k8s.example", c.Renewer.ServerURL)
		assert.Equal(t, []string{"authn"}, c.Renewer.Groups)
		assert.Equal(t, 2*time.Hour, c.Renewer.Duration)
		assert.Equal(t, 0.5, c.Renewer.Threshold)
		assert.Equal(t, "authn", c.Backfill.SelfUsername)
	}
}
