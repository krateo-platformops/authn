package usernames

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// byName answers Secret reads by name.
type byName struct {
	lookup
	secrets map[string]*corev1.Secret
	names   []string
}

func (b *byName) Secret(_ context.Context, name string) (*corev1.Secret, error) {
	b.names = append(b.names, name)
	return b.secrets[name], nil
}

func checkExact(t *testing.T, rc *rest.Config, naming storage.Naming, l kubeconfig.NameLookup, username string) (Response, string, bool) {
	t.Helper()
	ar, rec := auditlogtest.New(t)
	h := Route(rc, Options{Audience: "authn", Lookup: l, Audit: ar.WithNaming(naming), Naming: naming}).Handler()
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer t")
	resp := httptest.NewRecorder()
	auditlog.Middleware(h).ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	var out Response
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
	r := only(t, rec)
	return out, auditlogtest.String(r, "krateo.audit.object_ref.name"), has(r, "krateo.audit.object_ref.name")
}

// With exact naming the route reads both names, and the X/Y pair holds: a
// Secret of johndoe's under john.doe's legacy name makes john.doe
// unavailable. Its record names john.doe's exact Secret; a name that can't be
// exact names none. With legacy naming, john.doe is invalid, as on main.
func TestCheckWithExactNaming(t *testing.T) {
	rc := apiserver(t, review(caller), mappings(optedIn))
	exact := storage.Naming{Exact: true}
	y := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "johndoe-clientconfig",
		Annotations: map[string]string{storage.UsernameAnnotation: "johndoe", storage.ClaimAnnotation: "c"}}}

	l := &byName{secrets: map[string]*corev1.Secret{"johndoe-clientconfig": y}}
	out, name, _ := checkExact(t, rc, exact, l, "john.doe")
	assert.Equal(t, Response{Available: false, Reason: kubeconfig.UnavailableHeldLegacy}, out)
	assert.Equal(t, "john.doe-clientconfig", name)
	assert.Equal(t, []string{"john.doe-clientconfig", "johndoe-clientconfig"}, l.names)

	out, name, _ = checkExact(t, rc, exact, &byName{secrets: map[string]*corev1.Secret{"johndoe-clientconfig": y}}, "johndoe")
	assert.Equal(t, Response{Available: false, Reason: kubeconfig.UnavailableClaimed}, out)
	assert.Equal(t, "johndoe-clientconfig", name)

	out, name, _ = checkExact(t, rc, exact, &byName{}, "john.doe")
	assert.Equal(t, Response{Available: true}, out)
	assert.Equal(t, "john.doe-clientconfig", name)

	out, _, named := checkExact(t, rc, exact, &byName{}, "Alice.Smith")
	assert.Equal(t, Response{Available: false, Reason: kubeconfig.UnavailableInvalid}, out)
	assert.False(t, named, "a name that can't be exact names no Secret")

	out, _, named = checkExact(t, rc, storage.Naming{}, &byName{}, "john.doe")
	assert.Equal(t, Response{Available: false, Reason: kubeconfig.UnavailableInvalid}, out, "legacy naming, as main")
	assert.False(t, named)
}

// With exact naming the route still compares a claimed name with the request's
// claimant (authn#146 on #147): john.doe's exact Secret, claimed, answers
// claimedBy you or another, and its record says name_claimed_by_claimant or
// name_claimed_by_another, naming no other identity.
func TestCheckWithExactNamingAndAClaimant(t *testing.T) {
	rc := apiserver(t, review(caller), mappings(optedIn))
	exact := storage.Naming{Exact: true}
	kcUser := map[string]string{"strategy": "oidc", "issuer": kcIssuer, "subject": "user-1"}
	for _, tc := range []struct {
		name   string
		claim  string
		by     kubeconfig.ClaimedBy
		result string
	}{
		{"the expected user's claim", storage.EncodeClaim(storage.StrategyOIDC, kcIssuer, "user-1"), kubeconfig.ClaimedByYou, audit.CheckResultNameClaimedByClaimant},
		{"another's claim", storage.EncodeClaim(storage.StrategyOIDC, otherIssuer, otherSubject), kubeconfig.ClaimedByAnother, audit.CheckResultNameClaimedByAnother},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "john.doe-clientconfig",
				Annotations: map[string]string{storage.UsernameAnnotation: "john.doe", storage.ClaimAnnotation: tc.claim}}}
			l := &byName{secrets: map[string]*corev1.Secret{"john.doe-clientconfig": x}}
			ar, rec := auditlogtest.New(t)
			h := Route(rc, Options{Audience: "authn", Lookup: l, Audit: ar.WithNaming(exact), Naming: exact}).Handler()
			req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body(t, "john.doe", kcUser)))
			req.Header.Set("Authorization", "Bearer t")
			resp := httptest.NewRecorder()
			auditlog.Middleware(h).ServeHTTP(resp, req)
			require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

			var out Response
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
			assert.Equal(t, Response{Reason: kubeconfig.UnavailableClaimed, ClaimedBy: tc.by}, out)
			assert.Equal(t, []string{"john.doe-clientconfig"}, l.names, "the exact name answers first")
			r := only(t, rec)
			assert.Equal(t, tc.result, auditlogtest.String(r, audit.KeyCheckResult))
			assert.Equal(t, "john.doe-clientconfig", auditlogtest.String(r, "krateo.audit.object_ref.name"))
			for _, kv := range audittest.Attributes(r) {
				assert.NotContains(t, kv.Value.Emit(), otherSubject, "%s names the other identity", kv.Key)
			}
			assert.NotContains(t, resp.Body.String(), otherSubject, "no answer names the other identity")
		})
	}
}
