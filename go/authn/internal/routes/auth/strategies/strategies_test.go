package strategies

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The oidc entries advertise step-up only for an OIDCConfig whose
// spec.stepUp is set and valid, and the existing extensions stay as they are.
func TestOIDCStrategiesAdvertiseStepUp(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "krateo-system")

	item := func(name, stepUp string) string {
		spec := `"issuer":"https://idp.example","authorizationURL":"https://idp.example/auth","tokenURL":"https://idp.example/token",
			"redirectURI":"https://portal.example/auth","clientID":"portal"`
		if stepUp != "" {
			spec += `,"stepUp":` + stepUp
		}
		return `{"apiVersion":"oidc.authn.krateo.io/v1alpha1","kind":"OIDCConfig",
			"metadata":{"name":"` + name + `","namespace":"krateo-system"},"spec":{` + spec + `}}`
	}
	list := `{"apiVersion":"oidc.authn.krateo.io/v1alpha1","kind":"OIDCConfigList","metadata":{},"items":[` +
		item("plain", "") + `,` +
		item("kc", `{"acrValues":["gold","urn:kc:loa2"],"maxAge":"2m"}`) + `,` +
		item("broken", `{"acrValues":["gold"],"ttl":"1m"}`) + `]}`

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/oidc.authn.krateo.io/v1alpha1/namespaces/krateo-system/oidcconfigs" {
			http.NotFound(w, r) // the other strategies fail and are left out
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(list))
	}))
	t.Cleanup(api.Close)

	rec := httptest.NewRecorder()
	List(&rest.Config{Host: api.URL}).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Path, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var got []strategy
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	ext := map[string]map[string]string{}
	for _, s := range got {
		require.Equal(t, "oidc", s.Kind)
		ext[s.Name] = s.Extensions
	}
	require.Len(t, ext, 3)

	for name, e := range ext {
		assert.Contains(t, e["authCodeURL"], "https://idp.example/auth?", name)
		assert.Equal(t, "https://portal.example/auth", e["redirectURL"], name)
	}

	assert.Equal(t, "/oidc/stepup", ext["kc"]["stepUpPath"])
	assert.Equal(t, "gold urn:kc:loa2", ext["kc"]["stepUpAcrValues"])
	assert.Equal(t, "120", ext["kc"]["stepUpMaxAge"])

	for _, name := range []string{"plain", "broken"} {
		for _, k := range []string{"stepUpPath", "stepUpAcrValues", "stepUpMaxAge"} {
			assert.NotContains(t, ext[name], k, "%s advertises no step-up", name)
		}
	}
}
