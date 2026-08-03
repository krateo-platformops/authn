// Package telemetry wires up OpenTelemetry tracing and metrics for the authn
// service.
//
// Everything in this package is GATED behind explicit, default-OFF opt-in env
// vars. OTEL_ENABLED is the master gate (default false); OTEL_TRACING_ENABLED
// and OTEL_METRICS_ENABLED each default to OTEL_ENABLED when unset, and still
// override it when set explicitly. When both signals resolve to off, Setup is a
// complete no-op: no exporter is created, no provider is registered with the
// global otel package, and no propagator is installed. The off-path is
// therefore byte-identical to the pre-instrumentation behaviour (the default
// http.DefaultClient / http.DefaultTransport stay untouched, and
// otel.GetTextMapPropagator() keeps returning the no-op propagator).
package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/krateo-platformops/authn/internal/env"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	// EnvEnabled is the master OTel gate. Default: false. When set it becomes
	// the default for EnvTracingEnabled and EnvMetricsEnabled (each of which
	// still overrides it when set explicitly).
	EnvEnabled = "OTEL_ENABLED"
	// EnvTracingEnabled gates the tracing pipeline. Default: OTEL_ENABLED.
	EnvTracingEnabled = "OTEL_TRACING_ENABLED"
	// EnvMetricsEnabled gates the metrics pipeline. Default: OTEL_ENABLED.
	EnvMetricsEnabled = "OTEL_METRICS_ENABLED"
	// EnvOTLPEndpoint is the standard OTLP/HTTP collector endpoint
	// (e.g. "otel-collector.krateo-system.svc.cluster.local:4318").
	// Consumed by the OTLP/HTTP exporters via their own env handling.
	EnvOTLPEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"
)

// Enabled reports the master OTel gate (OTEL_ENABLED). Default: false.
func Enabled() bool {
	return env.Bool(EnvEnabled, false)
}

// ShutdownFunc flushes and releases any telemetry providers created by Setup.
// It is always safe to call (no-op when nothing was registered).
type ShutdownFunc func(context.Context) error

// TracingEnabled reports whether the tracing pipeline is opted in. It defaults
// to the master OTEL_ENABLED gate when OTEL_TRACING_ENABLED is unset.
func TracingEnabled() bool {
	return env.Bool(EnvTracingEnabled, Enabled())
}

// MetricsEnabled reports whether the metrics pipeline is opted in. It defaults
// to the master OTEL_ENABLED gate when OTEL_METRICS_ENABLED is unset.
func MetricsEnabled() bool {
	return env.Bool(EnvMetricsEnabled, Enabled())
}

// Setup conditionally initialises the OpenTelemetry tracing and/or metrics
// pipelines based on the default-OFF opt-in env vars.
//
// When neither pipeline is enabled it returns a no-op shutdown and registers
// nothing globally — the process behaves exactly as it did before OTel was
// added.
//
// When tracing is enabled it installs an OTLP/HTTP batch span exporter, a
// TracerProvider carrying service.name=<serviceName>/version, registers it via
// otel.SetTracerProvider, and installs a composite TraceContext+Baggage
// propagator via otel.SetTextMapPropagator.
//
// When metrics is enabled it installs an OTLP/HTTP metric exporter and a
// periodic-reader MeterProvider, registered via otel.SetMeterProvider.
func Setup(ctx context.Context, serviceName, version string) (ShutdownFunc, error) {
	tracing := TracingEnabled()
	metrics := MetricsEnabled()

	// Hard requirement: when nothing is opted in, register nothing globally.
	if !tracing && !metrics {
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		return func(context.Context) error { return nil }, err
	}

	var shutdowns []func(context.Context) error

	if tracing {
		shutdown, err := setupTracing(ctx, res)
		if err != nil {
			return func(context.Context) error { return nil }, err
		}
		shutdowns = append(shutdowns, shutdown)

		// Install the composite propagator so traceparent/tracestate/baggage
		// flow across the inbound and (instrumented) outbound HTTP hops.
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
	}

	if metrics {
		shutdown, err := setupMetrics(ctx, res)
		if err != nil {
			// Best effort cleanup of anything already wired (tracing).
			runShutdowns(ctx, shutdowns)
			return func(context.Context) error { return nil }, err
		}
		shutdowns = append(shutdowns, shutdown)
	}

	return func(ctx context.Context) error {
		return runShutdowns(ctx, shutdowns)
	}, nil
}

func setupTracing(ctx context.Context, res *resource.Resource) (func(context.Context) error, error) {
	// otlptracehttp reads OTEL_EXPORTER_OTLP_ENDPOINT (and related standard env
	// vars) on its own; no endpoint is hard-coded here.
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

func setupMetrics(ctx context.Context, res *resource.Resource) (func(context.Context) error, error) {
	exporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(30*time.Second),
		)),
	)
	otel.SetMeterProvider(mp)

	return mp.Shutdown, nil
}

func runShutdowns(ctx context.Context, shutdowns []func(context.Context) error) error {
	var errs []error
	for _, fn := range shutdowns {
		if fn == nil {
			continue
		}
		if err := fn(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
