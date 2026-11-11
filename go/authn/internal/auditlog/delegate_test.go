package auditlog

import (
	"net/http"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func agentMapping() *sav1alpha1.ServiceAccount {
	return &sav1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: "kagent", Namespace: "krateo-system", UID: "uid-map", ResourceVersion: "3", Generation: 2}}
}

// Every /delegate record shape conforms for the request writer, and Check
// catches each required key's removal (acceptance 3 and 4).
func TestDelegationRecordsConform(t *testing.T) {
	person := &jwtutil.UserInfo{Username: "alice", Principal: jwtutil.PrincipalHuman}
	chain := &jwtutil.Actor{Sub: "kagent", Principal: jwtutil.PrincipalAgent}
	for _, tc := range []struct {
		name    string
		subject *jwtutil.UserInfo
		chain   *jwtutil.Actor
		outcome string
	}{
		{"issued", person, chain, audit.OutcomeSuccess},
		{"refused: the mapping doesn't allow delegation", nil, nil, audit.OutcomeDenied},
		{"refused: the chain would be too deep", person, chain, audit.OutcomeDenied},
		{"signing failed", person, chain, audit.OutcomeFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, rec := newRecorder(t)
			req := get("/delegate")
			req.Method = http.MethodPost
			r.Delegation(req, agentMapping(), jwtutil.PrincipalAgent, tc.subject, tc.chain, tc.outcome)
			got := rec.Only(t)
			audittest.AssertConformant(t, audit.WriterRequest, got)
			audittest.AssertRequiredKeysDetected(t, audit.WriterRequest, got)

			attrs := audittest.Attributes(got)
			for key, want := range map[string]string{
				"krateo.action":                       ActionDelegate,
				"user.name":                           "kagent",
				"krateo.audit.verb":                   "create",
				"krateo.audit.object_ref.resource":    "serviceaccounts",
				"krateo.audit.object_ref.subresource": "token",
				"krateo.audit.object_ref.api_group":   sav1alpha1.Group,
				"krateo.audit.object_ref.name":        "kagent",
				"krateo.audit.outcome":                tc.outcome,
			} {
				v, _ := attr(t, attrs, key)
				assert.Equal(t, want, v.AsString(), key)
			}
			_, hasStatus := attr(t, attrs, "http.response.status_code")
			assert.False(t, hasStatus, "authn issues the token itself: no authority answered")
			dr, _ := attr(t, attrs, "krateo.audit.dry_run")
			assert.False(t, dr.AsBool(), "a real issuance")
			_, hasDryRun := attr(t, attrs, "krateo.audit.dry_run")
			assert.True(t, hasDryRun, "an issuance is a write, so it says whether it persisted")
			v, ok := attr(t, attrs, "krateo.audit.on_behalf_of.user.name")
			if tc.subject != nil {
				assert.Equal(t, "alice", v.AsString())
				d, _ := attr(t, attrs, "krateo.audit.delegation")
				assert.Equal(t, []string{"agent:kagent", "human:alice"}, d.AsStringSlice())
			} else {
				assert.False(t, ok, "no subject read yet, so nobody is acted for")
			}
		})
	}
}
