package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With a restActionRef, snowplow's answer completes the identity: the five
// fields authn reads override the ID token's, any other status field is
// ignored, and a failure is 500 RESTActionFailed. authn never writes to the
// cluster to resolve it (the legacy copy path is gone).
func TestRESTActionCompletesTheIdentity(t *testing.T) {
	type call struct{ method, path, token string }
	run := func(t *testing.T, code int, body string) (*httptest.ResponseRecorder, *stepUpGenerator, []call) {
		var calls []call
		snowplow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Extras map[string]string `json:"extras"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			calls = append(calls, call{r.Method, r.URL.Path, in.Extras["token"]})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(snowplow.Close)

		rc := oidcEnv(t, `"restActionRef":{"name":"enrich","namespace":"krateo-system"}`, nil)
		base := xcontext.BuildContext(context.Background(), xcontext.WithAccessToken("authn-jwt"))
		base = context.WithValue(base, restaction.RestActionContextKey("snowplowURL"), snowplow.URL)
		gen := &stepUpGenerator{notAfter: time.Now().Add(time.Hour)}
		route := Login(base, rc, LoginOptions{KubeconfigGenerator: gen, JwtDuration: time.Hour, JwtPrivateKey: failureKey(t), JwtKeyID: "k"})
		req := httptest.NewRequest(http.MethodGet, Path+"?name=kc", nil)
		req.Header.Set("X-Auth-Code", "code")
		req.Header.Set("X-Code-Verifier", testCodeVerifier)
		rec := httptest.NewRecorder()
		route.Handler().ServeHTTP(rec, req)
		return rec, gen, calls
	}

	t.Run("overrides the five fields and ignores the rest", func(t *testing.T) {
		rec, gen, calls := run(t, http.StatusOK, `{"status":{"groups":["ops"],"name":"Alice A.","department":"R&D","costCenter":42}}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Len(t, gen.sessions, 1)
		assert.Equal(t, []string{"ops"}, gen.sessions[0].GetGroups())
		assert.Equal(t, "Alice A.", gen.sessions[0].GetExtensions().Get("name"))
		require.Len(t, calls, 1, "one call to snowplow, no fallback")
		assert.Equal(t, call{http.MethodPost, "/call/read", "at"}, calls[0], "the user's access token, in the body")
	})

	t.Run("an answer that identifies no one is RESTActionIdentityInvalid", func(t *testing.T) {
		// Resolved, but groups isn't a list: for an administrator, not a retry.
		rec, gen, _ := run(t, http.StatusOK, `{"status":{"groups":"ops"}}`)
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		assert.Equal(t, "RESTActionIdentityInvalid", causeOf(t, rec))
		assert.Empty(t, gen.sessions, "nothing minted")
	})

	t.Run("a snowplow failure is RESTActionFailed", func(t *testing.T) {
		rec, gen, calls := run(t, http.StatusGatewayTimeout, `{"kind":"Status","status":"Failure","reason":"Timeout","message":"stage timed out","code":504}`)
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		assert.Equal(t, "RESTActionFailed", causeOf(t, rec))
		assert.Contains(t, rec.Body.String(), "snowplow answered 504 Timeout")
		assert.Empty(t, gen.sessions, "nothing minted")
		assert.Len(t, calls, 1, "no retry through a copy")
	})
}
