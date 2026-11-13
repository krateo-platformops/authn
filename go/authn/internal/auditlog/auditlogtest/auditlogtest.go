// Package auditlogtest wires an auditlog.Recorder to audittest's in-memory
// recorder, so a route's tests drive its emit site through the real SDK and
// check what it wrote.
package auditlogtest

import (
	"context"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

type provider struct {
	embedded.LoggerProvider
	rec *audittest.Recorder
}

func (p provider) Logger(name string, _ ...log.LoggerOption) log.Logger { return p.rec.Logger(name) }

// New returns a Recorder whose records land in the returned audittest
// recorder. Every namespace reads as not a preview sandbox.
func New(t testing.TB) (*auditlog.Recorder, *audittest.Recorder) {
	t.Helper()
	rec := audittest.NewRecorder(t)
	return auditlog.New(provider{rec: rec}, func(context.Context, string) (bool, bool) { return false, true }), rec
}

// Only returns the single record, after checking that it conforms for the
// request writer and that Check catches each required key's removal.
func Only(t testing.TB, rec *audittest.Recorder) sdklog.Record {
	t.Helper()
	r := rec.Only(t)
	audittest.AssertConformant(t, audit.WriterRequest, r)
	audittest.AssertRequiredKeysDetected(t, audit.WriterRequest, r)
	return r
}

// String returns the record's string attribute key, "" when absent.
func String(r sdklog.Record, key string) string {
	for _, kv := range audittest.Attributes(r) {
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}
	return ""
}

// Created is the write a fake generator reports for username's session
// Secret: created, as the apiserver answers a create.
func Created(username string) storage.Written {
	return storage.Written{Namespace: "krateo-system", Name: storage.ClientConfigSecretName(username),
		UID: "uid-" + username, ResourceVersion: "1", Verb: "create", StatusCode: 201}
}

// WriteFailed is the write a fake generator reports when username's session
// Secret's create was sent and the apiserver answered code: the verb and the
// answer, nothing stored.
func WriteFailed(username string, code int) storage.Written {
	return storage.Written{Namespace: "krateo-system", Name: storage.ClientConfigSecretName(username),
		Verb: "create", StatusCode: code}
}

// OnlyWriteFailed returns the single record, after checking that it conforms
// for the request writer (Only) and records a failed issuance as WriteFailed
// reports it: action, outcome failure, username's Secret, the create sent and
// the apiserver's code, and no stored uid.
func OnlyWriteFailed(t testing.TB, rec *audittest.Recorder, action, username string, code int) sdklog.Record {
	t.Helper()
	r := Only(t, rec)
	assert.Equal(t, action, String(r, "krateo.action"))
	assert.Equal(t, audit.OutcomeFailure, String(r, "krateo.audit.outcome"))
	assert.Equal(t, storage.ClientConfigSecretName(username), String(r, "krateo.audit.object_ref.name"))
	assert.Equal(t, "create", String(r, audit.KeyVerb))
	assert.Empty(t, String(r, audit.KeyObjectUID), "nothing was stored")
	got, ok := Int(r, "http.response.status_code")
	assert.True(t, ok, "the apiserver's answer is recorded")
	assert.Equal(t, int64(code), got)
	return r
}

// Int returns the record's integer attribute key, and whether it is present.
func Int(r sdklog.Record, key string) (int64, bool) {
	for _, kv := range audittest.Attributes(r) {
		if string(kv.Key) == key {
			return kv.Value.AsInt64(), true
		}
	}
	return 0, false
}

// NewController returns a Controller acting as serviceAccount, whose records
// land in the returned audittest recorder.
func NewController(t testing.TB, serviceAccount string) (*auditlog.Controller, *audittest.Recorder) {
	t.Helper()
	rec := audittest.NewRecorder(t)
	return auditlog.NewController(provider{rec: rec}, serviceAccount, func(context.Context, string) (bool, bool) { return false, true }), rec
}
