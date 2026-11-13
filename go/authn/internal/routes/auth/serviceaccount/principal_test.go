package serviceaccount

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// A service's token carries the kind its mapping declares in
// spec.principal, and service when it declares none.
func TestHandlerSignsTheMappingsPrincipal(t *testing.T) {
	for declared, want := range map[string]jwtutil.Principal{
		"":           jwtutil.PrincipalService,
		"service":    jwtutil.PrincipalService,
		"agent":      jwtutil.PrincipalAgent,
		"controller": jwtutil.PrincipalController,
	} {
		t.Run("declared "+declared, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", "krateo-system")
			m := mappingCdc
			if declared != "" {
				m = strings.Replace(m, `"groups":["krateo:cdc"]`, `"groups":["krateo:cdc"],"principal":"`+declared+`"`, 1)
				require.Contains(t, m, declared)
			}
			rep := defaultReplies()
			rep.mappings = mappingList(m)
			srv := fakeAPIServer(t, rep)
			defer srv.Close()

			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			gen := &fakeGenerator{}
			route := Login(&rest.Config{Host: srv.URL}, LoginOptions{
				KubeconfigGenerator: gen,
				JwtDuration:         time.Hour,
				JwtPrivateKey:       key,
				JwtKeyID:            "test-key",
			})

			req := httptest.NewRequest(http.MethodPost, Path, nil)
			req.Header.Set("Authorization", "Bearer projected-sa-token")
			rec := httptest.NewRecorder()
			route.Handler().ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			var out struct {
				AccessToken string `json:"accessToken"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
			nfo, err := jwtutil.Validate(&key.PublicKey, out.AccessToken)
			require.NoError(t, err)
			assert.Equal(t, want, nfo.Principal)
			// The same kind labels the stored Secret (authn#144, with exact
			// names on): the route hands it to the generator.
			assert.Equal(t, []string{string(want)}, gen.principals)
		})
	}
}
