package telemetry

import (
	"context"

	"github.com/krateo-platformops/authn/internal/env"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// EnvLogsEnabled gates the OTLP logs pipeline, which carries authn's audit
// records (AUDIT-4) and nothing else. Default: OTEL_ENABLED.
//
// Logs go to OTEL_EXPORTER_OTLP_LOGS_ENDPOINT when it is set, else to
// OTEL_EXPORTER_OTLP_ENDPOINT, as the OTLP exporter reads them. The chart sets
// the latter for every signal: the node-local collector agent,
// http://$(HOST_IP):4318, whose logs/audit pipeline writes krateo_audit.
const EnvLogsEnabled = "OTEL_LOGS_ENABLED"

// LogsEnabled reports whether the logs pipeline is opted in. It defaults to the
// master OTEL_ENABLED gate when OTEL_LOGS_ENABLED is unset.
func LogsEnabled() bool {
	return env.Bool(EnvLogsEnabled, Enabled())
}

// SetupLogs builds the LoggerProvider audit records are written to, or returns
// nil and a no-op shutdown when the logs pipeline is off. A nil provider makes
// every audit Emit a no-op.
//
// The provider is returned, not registered globally: authn writes no OTel logs
// other than audit records, and keeping it out of the global keeps any library
// that logs through the global provider out of the audit trail.
func SetupLogs(ctx context.Context, serviceName, version string) (log.LoggerProvider, ShutdownFunc, error) {
	noop := func(context.Context) error { return nil }
	if !LogsEnabled() {
		return nil, noop, nil
	}
	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		return nil, noop, err
	}
	exporter, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, noop, err
	}
	counted, err := countFailures(exporter, otel.GetMeterProvider())
	if err != nil {
		return nil, noop, err
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(counted)),
	)
	return lp, lp.Shutdown, nil
}

// MetricAuditExportFailed counts audit records an export attempt failed to
// deliver. Export never blocks a login: the SDK retries and then drops, and this
// counter is how a dropped record shows up as a number rather than a silent gap.
// It carries no attribute, so no identity can reach it.
const MetricAuditExportFailed = "authn.audit.export.failed"

// failureCountingExporter counts the records of every failed Export.
type failureCountingExporter struct {
	sdklog.Exporter
	failed metric.Int64Counter
}

func countFailures(e sdklog.Exporter, mp metric.MeterProvider) (sdklog.Exporter, error) {
	c, err := mp.Meter("github.com/krateo-platformops/authn/internal/telemetry").Int64Counter(MetricAuditExportFailed,
		metric.WithUnit("{record}"),
		metric.WithDescription("Audit records an OTLP export attempt failed to deliver."))
	if err != nil {
		return nil, err
	}
	return failureCountingExporter{Exporter: e, failed: c}, nil
}

func (e failureCountingExporter) Export(ctx context.Context, records []sdklog.Record) error {
	err := e.Exporter.Export(ctx, records)
	if err != nil {
		e.failed.Add(ctx, int64(len(records)))
	}
	return err
}
