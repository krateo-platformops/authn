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

// NewController returns a Controller acting as serviceAccount, whose records
// land in the returned audittest recorder.
func NewController(t testing.TB, serviceAccount string) (*auditlog.Controller, *audittest.Recorder) {
	t.Helper()
	rec := audittest.NewRecorder(t)
	return auditlog.NewController(provider{rec: rec}, serviceAccount, func(context.Context, string) (bool, bool) { return false, true }), rec
}
