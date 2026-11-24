package stepupsweep

import (
	"context"
	"testing"
	"time"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

// authn#167: an expired delegated credential is deleted like an expired
// step-up one, and recorded as its own action. A valid one, one within the
// grace, and a Secret merely starting like a delegated name stay.
func TestSweepDeletesExpiredDelegatedSecrets(t *testing.T) {
	expired := storage.DelegatedSecretName("alice", "dispatcher", []string{"devs"})
	valid := storage.DelegatedSecretName("alice", "ide-agent", []string{"devs"})
	inGrace := storage.DelegatedSecretName("bob", "dispatcher", []string{"devs"})
	c := fake.NewSimpleClientset(
		secret(expired, "krateo-system", certData(t, now.Add(-time.Hour))),
		secret(valid, "krateo-system", certData(t, now.Add(10*time.Minute))),
		secret(inGrace, "krateo-system", certData(t, now.Add(-2*time.Minute))),
		secret("delegated-not-a-digest", "krateo-system", certData(t, now.Add(-time.Hour))),
	)
	ctl, records := auditlogtest.NewController(t, "system:serviceaccount:krateo-system:authn")
	res, err := Sweep(context.Background(), Options{Client: c, Namespaces: []string{"krateo-system"},
		Now: func() time.Time { return now }, Log: zerolog.Nop(), Audit: ctl})
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{valid, inGrace, "delegated-not-a-digest"}, names(t, c, "krateo-system"))
	assert.Equal(t, Result{Scanned: 3, Deleted: 1}, res)

	r := records.Only(t)
	audittest.AssertConformant(t, audit.WriterController, r)
	audittest.AssertRequiredKeysDetected(t, audit.WriterController, r)
	assert.Equal(t, auditlog.ActionDelegateExpired, auditlogtest.String(r, "krateo.action"))
	assert.Equal(t, expired, auditlogtest.String(r, "krateo.audit.object_ref.name"))
	assert.Equal(t, "success", auditlogtest.String(r, "krateo.audit.outcome"))
}
