package telemetry

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// The logs gate defaults to the master gate and can be set on its own; off,
// SetupLogs builds nothing, so every audit Emit is a no-op.
func TestLogsGate(t *testing.T) {
	for _, tc := range []struct {
		master, logs string
		want         bool
	}{
		{"", "", false},
		{"true", "", true},
		{"true", "false", false},
		{"", "true", true},
	} {
		t.Setenv(EnvEnabled, tc.master)
		t.Setenv(EnvLogsEnabled, tc.logs)
		assert.Equal(t, tc.want, LogsEnabled(), "OTEL_ENABLED=%q OTEL_LOGS_ENABLED=%q", tc.master, tc.logs)
	}

	t.Setenv(EnvEnabled, "")
	t.Setenv(EnvLogsEnabled, "false")
	lp, shutdown, err := SetupLogs(context.Background(), "authn", "test")
	require.NoError(t, err)
	assert.Nil(t, lp, "off: no provider")
	assert.NoError(t, shutdown(context.Background()))
}

type failingExporter struct{ sdklog.Exporter }

func (failingExporter) Export(context.Context, []sdklog.Record) error {
	return errors.New("collector down")
}

// A failed export counts the records it dropped, so a gap in the audit trail
// shows up as a number.
func TestFailedExportsAreCounted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	e, err := countFailures(failingExporter{}, mp)
	require.NoError(t, err)

	require.Error(t, e.Export(context.Background(), make([]sdklog.Record, 3)))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != MetricAuditExportFailed {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				total += dp.Value
				assert.Zero(t, dp.Attributes.Len(), "no attribute, so no identity")
			}
		}
	}
	assert.Equal(t, int64(3), total)
}
