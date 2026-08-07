---
type: Log
title: authn — log
description: Curated chronological history — notable changes, decisions and incidents; release notes stay in GitHub Releases.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [history]
timestamp: 2026-08-07T00:00:00Z
---

# Log

Curated history, newest first. Durable decisions live in
[`docs/design/`](./design/); the code-traced internals corpus is
[architecture](./architecture.md) / [behavior](./behavior.md) /
[gotchas](./gotchas.md).

## 2026-08-07 — adopted the Krateo Documentation Standard

This bundle: root `docs/` core set + `examples/` + thin README. The internals corpus
(architecture/behavior/gotchas) was re-verified line-by-line against the source: the
`main.go` and `routes.go` citations had drifted since the OpenTelemetry
instrumentation landed (the docs predated it entirely), the `oidc/support.go`
citations had shifted ~8 lines, and the OAuthConfig type was attributed to the base
`apis/authn/oauth/types.go` while the served kind (with `restActionRef`/`graphics`)
lives in `apis/authn/oauth/v1alpha1/`. `docs/llms.txt` still routed the deployment
view to a long-dead separate chart repo — the chart has lived in `helm/` since the
monorepo fold. All re-grounded; the intra-service-auth design doc is now a living
decision record (`status: implemented`).

## 2026-08-03/04 — 0.26.0: the monorepo fold + org independence

The separate chart repo was collapsed into `helm/` (one version line: image + both
charts ship from one tag), the app moved into `go/authn/`, and Go module identity
migrated to `github.com/krateo-platformops/authn`; CI moved to the org's shared
reusable workflows (multi-arch image build, Go checks + CRD-drift guard, security).
Lesson paid for en route: the migration was first tagged `v0.25.0` — the `v` prefix
matches no release-workflow trigger, so it shipped nothing; `0.26.0` is the release
that followed. Tag without `v`, always ([release](./release.md)).

## 2026-06-25 — gated, default-off OpenTelemetry (#9, #10)

Traces + metrics + trace/log correlation landed behind the `OTEL_ENABLED` master gate
(per-signal `OTEL_TRACING_ENABLED` / `OTEL_METRICS_ENABLED` overrides, OTel-Go
v1.44). Off-path is byte-identical to the un-instrumented service; `/health` is
filtered out of tracing. The CORS allowlist grew the W3C trace-context headers
(`traceparent`/`tracestate`/`baggage`) so the browser→authn hop can carry a trace.

## 2026-06-20 — 0.23.0: the `serviceaccount` login strategy

Kubernetes intra-service auth shipped as designed
([decision](./design/kubernetes-intra-service-auth.md)): a backend service exchanges
its own projected, audience-bound SA token (validated via the TokenReview API)
against a `ServiceAccount` allowlist CRD for the same JWT + kubeconfig human users
get — no signing-key sprawl, RBAC stays standard Kubernetes on the mapping's groups.
The chart gained `tokenreviews:create` + allowlist-read RBAC (#25). First consumers:
core-provider's cdc and snowplow's prewarm seed.

## Earlier (the 0.22.x line and before)

The five-strategy shape settled: per-strategy config CRDs, the CSR-minted per-user
client-cert kubeconfig as the one identity output, RESTAction-based identity
compilation for OAuth2/OIDC via snowplow, and the crds-subchart versioning reversal
(CRD chart released at the main chart's tag — hand-copied CRD drift once broke portal
login). Release notes: GitHub Releases.
