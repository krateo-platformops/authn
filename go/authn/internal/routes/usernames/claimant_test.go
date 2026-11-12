package usernames

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	kcIssuer = "https://keycloak.example.test/realms/krateo"
	// The other identity holding a name: neither its issuer nor its subject
	// may appear in any answer.
	otherIssuer  = "https://zz-other-issuer.example.test/realms/x"
	otherSubject = "zz-other-subject"
)

func claimedSecret(claim string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{storage.ClaimAnnotation: claim}}}
}

func body(t *testing.T, username string, claimant any) string {
	t.Helper()
	m := map[string]any{"username": username}
	if claimant != nil {
		m["claimant"] = claimant
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return string(b)
}

// A caller that names the identity it expects learns whether a claimed name
// is that identity's, and never who else holds it.
func TestCheckWithAClaimant(t *testing.T) {
	rc := apiserver(t, review(caller), mappings(optedIn))
	kcUser := map[string]string{"strategy": "oidc", "issuer": kcIssuer, "subject": "user-1"}
	mine := storage.EncodeClaim(storage.StrategyOIDC, kcIssuer, "user-1")
	theirs := storage.EncodeClaim(storage.StrategyOIDC, otherIssuer, otherSubject)
	for _, tc := range []struct {
		name     string
		l        lookup
		claimant any
		want     Response
	}{
		{"claimed by the expected user", lookup{secret: claimedSecret(mine)}, kcUser,
			Response{Reason: "name_claimed", ClaimedBy: "you"}},
		{"claimed by another", lookup{secret: claimedSecret(theirs)}, kcUser,
			Response{Reason: "name_claimed", ClaimedBy: "another"}},
		{"no claimant: no claimedBy", lookup{secret: claimedSecret(mine)}, nil,
			Response{Reason: "name_claimed"}},
		{"available, with a claimant: no claimedBy", lookup{}, kcUser, Response{Available: true}},
		{"bound, with a claimant: no claimedBy", lookup{bound: true}, kcUser, Response{Reason: "name_bound"}},
		{"held without a claim, with a claimant: no claimedBy", lookup{secret: &corev1.Secret{}}, kcUser,
			Response{Reason: "name_held_legacy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := check(t, rc, &tc.l, "projected-sa-token", body(t, "alice", tc.claimant))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var got Response
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, tc.want, got)
			assert.NotContains(t, rec.Body.String(), otherIssuer, "no answer names the claimant")
			assert.NotContains(t, rec.Body.String(), otherSubject, "no answer names the claimant")
			if tc.want.ClaimedBy == "" {
				assert.NotContains(t, rec.Body.String(), "claimedBy")
			}
		})
	}
}

// A claimant that can't name an identity is a bad request, refused before
// any read.
func TestCheckRefusesABadClaimant(t *testing.T) {
	rc := apiserver(t, review(caller), mappings(optedIn))
	for name, claimant := range map[string]any{
		"no strategy":       map[string]string{"issuer": kcIssuer, "subject": "user-1"},
		"no issuer":         map[string]string{"strategy": "oidc", "subject": "user-1"},
		"no subject":        map[string]string{"strategy": "oidc", "issuer": kcIssuer},
		"an unknown kind":   map[string]string{"strategy": "saml", "issuer": kcIssuer, "subject": "user-1"},
		"authn's own":       map[string]string{"strategy": "self", "issuer": kcIssuer, "subject": "user-1"},
		"not an object":     "oidc",
		"an empty claimant": map[string]string{},
	} {
		t.Run(name, func(t *testing.T) {
			l := &lookup{secret: claimedSecret(storage.EncodeClaim(storage.StrategyOIDC, kcIssuer, "user-1"))}
			rec := check(t, rc, l, "projected-sa-token", body(t, "alice", claimant))
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, "InvalidRequestBody", cause(t, rec))
			assert.Zero(t, l.reads, "a bad request reads nothing")
			assert.NotContains(t, rec.Body.String(), `"available"`)
		})
	}
}
