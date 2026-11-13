package auditlog

import (
	"context"
	"errors"
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

// The record of authn's own certificate write conforms for the controller
// writer, with the verb and status plumbing's StoreWritten reported. A renewal
// that failed before the Secret write (no verb) is not recorded.
func TestServiceCertIssuedRecordsConform(t *testing.T) {
	ref := SecretRef{Namespace: "krateo-system", Name: "authn-clientconfig", UID: "uid-a", ResourceVersion: "3"}
	for _, tc := range []struct {
		name    string
		verb    string
		code    int
		err     error
		outcome string
	}{
		{"created", "create", 201, nil, audit.OutcomeSuccess},
		{"updated after the create's 409", "update", 200, nil, audit.OutcomeSuccess},
		{"refused", "update", 403, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, ref.Name, nil), audit.OutcomeFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := audittest.NewRecorder(t)
			c := NewController(&provider{rec: rec}, authnSA, func(context.Context, string) (bool, bool) { return false, true })
			c.ServiceCertIssued(context.Background(), ref, tc.verb, tc.code, tc.err)
			got := rec.Only(t)
			audittest.AssertConformant(t, audit.WriterController, got)
			audittest.AssertRequiredKeysDetected(t, audit.WriterController, got)
			attrs := audittest.Attributes(got)
			v, _ := attr(t, attrs, "krateo.action")
			assert.Equal(t, ActionServiceCertIssued, v.AsString())
			v, _ = attr(t, attrs, "krateo.audit.verb")
			assert.Equal(t, tc.verb, v.AsString())
			v, _ = attr(t, attrs, "krateo.audit.outcome")
			assert.Equal(t, tc.outcome, v.AsString())
			v, _ = attr(t, attrs, "http.response.status_code")
			assert.Equal(t, int64(tc.code), v.AsInt64())
		})
	}

	t.Run("a verb that couldn't be told is omitted and marked, never guessed", func(t *testing.T) {
		rec := audittest.NewRecorder(t)
		c := NewController(&provider{rec: rec}, authnSA, func(context.Context, string) (bool, bool) { return false, true })
		c.ServiceCertIssued(context.Background(), SecretRef{Namespace: "krateo-system", Name: "authn-clientconfig"}, "", 0,
			errors.New("the CSR was not approved"))
		got := rec.Only(t)
		audittest.AssertConformant(t, audit.WriterController, got, audittest.AllowIncomplete(audit.KeyVerb))
		attrs := audittest.Attributes(got)
		_, hasVerb := attr(t, attrs, audit.KeyVerb)
		assert.False(t, hasVerb, "no verb is invented")
		v, _ := attr(t, attrs, audit.KeyIncomplete)
		assert.Contains(t, v.AsString(), "verb", "the gap is marked")
		v, _ = attr(t, attrs, "krateo.audit.outcome")
		assert.Equal(t, audit.OutcomeFailure, v.AsString())
	})

	t.Run("a status that isn't known is omitted, never assumed", func(t *testing.T) {
		rec := audittest.NewRecorder(t)
		c := NewController(&provider{rec: rec}, authnSA, func(context.Context, string) (bool, bool) { return false, true })
		c.ServiceCertIssued(context.Background(), SecretRef{Namespace: "krateo-system", Name: "authn-clientconfig"}, "create", 0, nil)
		_, has := attr(t, audittest.Attributes(rec.Only(t)), "http.response.status_code")
		assert.False(t, has)
	})
}

// A key the backfill left as found is one denied update per key, carrying
// audit's kept_existing_value and the key as <kind>:<key>, conformant for the
// controller writer. Nothing was sent: no method, no status code.
func TestIdentityKeptRecordsConform(t *testing.T) {
	ref := SecretRef{Namespace: "krateo-system", Name: "alice-clientconfig", UID: "uid-a", ResourceVersion: "7"}
	for _, tc := range []struct{ kind, key, want string }{
		{audit.MetadataKindAnnotation, "authn.krateo.io/username", "annotation:authn.krateo.io/username"},
		{audit.MetadataKindLabel, "authn.krateo.io/principal", "label:authn.krateo.io/principal"},
		{audit.MetadataKindLabel, "authn.krateo.io/username-label", "label:authn.krateo.io/username-label"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			rec := audittest.NewRecorder(t)
			c := NewController(&provider{rec: rec}, authnSA, func(context.Context, string) (bool, bool) { return false, true })
			c.IdentityKept(context.Background(), ref, tc.kind, tc.key)
			got := rec.Only(t)
			audittest.AssertConformant(t, audit.WriterController, got)
			audittest.AssertRequiredKeysDetected(t, audit.WriterController, got)

			attrs := audittest.Attributes(got)
			for key, want := range map[string]string{
				"user.name":                      authnSA,
				"krateo.action":                  ActionIdentityInconsistent,
				"krateo.audit.verb":              "update",
				"krateo.audit.outcome":           audit.OutcomeDenied,
				"krateo.audit.denial_reason":     audit.DenialReasonKeptExistingValue,
				"krateo.audit.authorization_key": tc.want,
				audit.KeyObjectName:              ref.Name,
			} {
				v, ok := attr(t, attrs, key)
				assert.True(t, ok, "%s is recorded", key)
				assert.Equal(t, want, v.AsString(), key)
			}
			for _, absent := range []string{"http.request.method", "http.response.status_code"} {
				_, ok := attr(t, attrs, absent)
				assert.False(t, ok, "%s: nothing was sent", absent)
			}
			assert.Equal(t, msgIdentityKept, got.Body().AsString())
		})
	}
}

// The kind is the key's, not inferred from its name: the username annotation's
// name under the label kind isn't a declared key. That record is still
// written, without the key, and Check reports it, so a mismatched bump shows
// up as a non-conformant record instead of a refusal going unrecorded.
func TestIdentityKeptOfAnUndeclaredKeyIsRecordedAndCaught(t *testing.T) {
	rec := audittest.NewRecorder(t)
	c := NewController(&provider{rec: rec}, authnSA, func(context.Context, string) (bool, bool) { return false, true })
	c.IdentityKept(context.Background(), SecretRef{Namespace: "krateo-system", Name: "alice-clientconfig"},
		audit.MetadataKindLabel, "authn.krateo.io/username")
	got := rec.Only(t)
	attrs := audittest.Attributes(got)
	_, ok := attr(t, attrs, "krateo.audit.authorization_key")
	assert.False(t, ok, "no key is spelled for an undeclared one")
	vs := audit.Check(audit.WriterController, attrs)
	assert.Contains(t, vs, audit.Violation{Key: "krateo.audit.authorization_key", Reason: audit.ReasonMissing})
}
