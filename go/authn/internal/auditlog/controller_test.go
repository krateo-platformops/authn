package auditlog

import (
	"context"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const authnSA = "system:serviceaccount:krateo-system:authn"

// The sweep's records conform for the controller writer, carry authn's
// ServiceAccount as the actor, and carry the status the apiserver answered or
// none at all (acceptance 3 and 4, the background exception).
func TestStepUpExpiredRecordsConform(t *testing.T) {
	ref := SecretRef{Namespace: "krateo-system", Name: "alice-clientconfig-stepup", UID: "uid-s", ResourceVersion: "9"}
	for _, tc := range []struct {
		name       string
		code       int
		err        error
		outcome    string
		wantStatus int64
	}{
		{"deleted (200)", 200, nil, audit.OutcomeSuccess, 200},
		{"deleted (202, finalizers)", 202, nil, audit.OutcomeSuccess, 202},
		{"rewritten meanwhile (409)", 0, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, ref.Name, nil), audit.OutcomeFailure, 409},
		{"status unknown: omitted", 0, nil, audit.OutcomeSuccess, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := audittest.NewRecorder(t)
			p := &provider{rec: rec}
			c := NewController(p, authnSA, func(context.Context, string) (bool, bool) { return false, true })
			assert.Equal(t, ScopeController, p.scope)
			c.StepUpExpired(context.Background(), ref, tc.code, tc.err)
			got := rec.Only(t)
			audittest.AssertConformant(t, audit.WriterController, got)
			audittest.AssertRequiredKeysDetected(t, audit.WriterController, got)

			attrs := audittest.Attributes(got)
			v, _ := attr(t, attrs, "user.name")
			assert.Equal(t, authnSA, v.AsString())
			v, _ = attr(t, attrs, "krateo.audit.outcome")
			assert.Equal(t, tc.outcome, v.AsString())
			v, ok := attr(t, attrs, "http.response.status_code")
			if tc.wantStatus == 0 {
				assert.False(t, ok, "an unknown status is omitted, never assumed")
			} else {
				assert.Equal(t, tc.wantStatus, v.AsInt64())
			}
			assert.Contains(t, []string{msgSwept, msgSweepError}, got.Body().AsString())
		})
	}
}
