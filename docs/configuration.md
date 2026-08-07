---
type: Configuration
title: authn — configuration
description: The whole config surface — Helm values, the env-var ConfigMap contract, flags and the OTel gates — with defaults.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [helm, values, env, flags]
timestamp: 2026-08-07T00:00:00Z
---

# Configuration

Everything is driven by the `authn` Helm chart
([`helm/authn/values.yaml`](../helm/authn/values.yaml)). The authoritative
machine-readable surface is
[`helm/authn/values.schema.json`](../helm/authn/values.schema.json) — every value is
typed and validated there; this page explains, it does not re-enumerate.

## The env contract

The container takes **no direct `env:` array**. Every value that reaches the process
goes through `envFrom`
([`deployment.yaml`](../helm/authn/templates/deployment.yaml)):

1. the chart-managed ConfigMap
   ([`configmap.yaml`](../helm/authn/templates/configmap.yaml)) — `AUTHN_PORT` (from
   `service.port`), `AUTHN_NAMESPACE` + `POD_NAMESPACE` (the release namespace),
   plus everything under `.Values.env`;
2. the JWT signing-key Secret — `jwtSignKeySecretName` (default `jwt-sign-key`, key
   `JWT_SIGN_KEY`); the pod does not start without it.

A `checksum/configmap` pod annotation rolls the Deployment when the ConfigMap
changes. Every flag of the binary has an env fallback (`go/authn/main.go:49-80`), so
`env.*` is the whole runtime surface.

## Helm values (top level)

| Value | Default | Effect |
|---|---|---|
| `image.registry` / `image.repository` | `ghcr.io` / `krateo-platformops/authn` | The app image. `global.imageRegistry` relocates the registry host for mirror/air-gapped installs (repository path preserved). |
| `image.tag` | `""` (= chart `appVersion`) | Pin only to diverge from the released pairing. |
| `service.type` / `service.port` | `ClusterIP` / `8082` | One port serves logins, `/strategies` and probes; the port value feeds `AUTHN_PORT`. |
| `replicaCount` | `1` | With `autoscaling.enabled: false` (default). |
| `livenessProbe` / `readinessProbe` | `GET /health` | `/health` flips 200 once the listener goroutine starts, 503 on shutdown — process lifecycle only ([gotchas](./gotchas.md)). |
| `ingress` | `enabled: false` | Standard chart ingress if you need it. |
| `jwtSignKeySecretName` | `jwt-sign-key` | Secret holding `JWT_SIGN_KEY` (shared platform-wide with the JWT validators). |
| `serviceAccount.create` | `true` | The SA the CSR/TokenReview ClusterRoles bind to. |
| `env.*` | see below | Rendered into the ConfigMap. |

## `env.*` — the runtime knobs

Chart defaults first, then the env vars the binary reads beyond what the chart sets
(all fallbacks of flags in `go/authn/main.go`):

| Env var | Default | Effect |
|---|---|---|
| `AUTHN_KUBECONFIG_SERVER_URL` | chart: `https://kube-apiserver:6443` | The apiserver URL written into every generated kubeconfig — **set it to a reachable endpoint**. |
| `AUTHN_KUBECONFIG_CLUSTER_NAME` | `krateo` | Cluster name in the generated kubeconfig. |
| `AUTHN_KUBECONFIG_CRT_EXPIRES_IN` | `24h` | Minted client-cert lifetime — and the login JWT lifetime (same knob wires both). |
| `AUTHN_CORS` | `true` | Permissive `*`-origin CORS for the browser hop (allows `X-Auth-Code` + W3C trace-context headers). |
| `AUTHN_DEBUG` | chart: `true` | Verbose (debug-level) logging. |
| `AUTHN_DUMP_ENV` | chart: `true` | Dump env vars in the debug boot log. |
| `AUTHN_PORT` | `8082` (chart sets = `service.port`) | Listen port. |
| `AUTHN_NAMESPACE` | chart: release namespace | Where generated `AuthInfo` Secrets are stored. |
| `POD_NAMESPACE` | chart: release namespace | The operator namespace — **all config CRs are resolved here**. |
| `AUTHN_USERNAME` | `authn` | The service's own identity for calling snowplow RESTActions. |
| `AUTHN_SERVICEACCOUNT_AUDIENCE` | `authn` | Audience the projected SA token must carry for `/serviceaccount/login`. |
| `JWT_SIGN_KEY` | (from the Secret) | JWT signing key; without it no `accessToken` is issued ([gotchas](./gotchas.md)). |
| `SNOWPLOW_SERVICE_HOST` / `SNOWPLOW_SERVICE_PORT` | unset / `8081` | Preferred snowplow endpoint source; beware the resolution quirk ([gotchas](./gotchas.md)). |
| `URL_SNOWPLOW` | `http://snowplow.krateo-system.svc.cluster.local:8081` | Fallback snowplow URL when the SERVICE_HOST pair is unset. |
| `OTEL_ENABLED` | `false` | Master OpenTelemetry gate; tracing and metrics each default to it. |
| `OTEL_TRACING_ENABLED` / `OTEL_METRICS_ENABLED` | = `OTEL_ENABLED` | Per-signal overrides (`go/authn/internal/telemetry/telemetry.go:36-44`). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (SDK standard) | OTLP/HTTP collector endpoint when telemetry is on. |

Flags mirror all of the above (`--port`, `--cert-expires`, `--jwt-sign-key`,
`--serviceaccount-audience`, `--otel-tracing`, `--kubeconfig` for out-of-cluster
runs, …) — flags win over env ([architecture](./architecture.md)).

## The CRDs chart

`authn-crds` ([`helm/authn-crds/`](../helm/authn-crds/)) has no configuration: it
installs the five `*.authn.krateo.io` CRDs ([api](./api.md)). It is deliberately
**not** a dependency of the app chart, so CRD ownership stays with its own release.
