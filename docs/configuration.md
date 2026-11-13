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
   `AUTHN_EXACT_USERNAMES` (from `exactUsernames.enabled`), plus everything under
   `.Values.env`;
2. the JWT signing-key Secret — `jwt.signKeySecretName` (default `authn-jwt-signing-key`, key
   `jwt.signKeySecretKey` / `private.pem`), mounted as a **file** (not injected as an
   env value) and read via `JWT_SIGN_KEY_FILE`; the pod does not start without it. See
   [jwt-jwks](./jwt-jwks.md).

A `checksum/configmap` pod annotation rolls the Deployment when the ConfigMap
changes. Every flag of the binary has an env fallback (`go/authn/main.go:49-80`), so
`env.*` is the whole runtime surface.

## Helm values (top level)

| Value | Default | Effect |
|---|---|---|
| `image.registry` / `image.repository` | `ghcr.io` / `krateo-platformops/authn` | The app image. `global.imageRegistry` relocates the registry host for mirror/air-gapped installs (repository path preserved). |
| `image.tag` | `""` (= chart `appVersion`) | Pin only to diverge from the released pairing. |
| `service.type` / `service.port` | `ClusterIP` / `8082` | The public port serves logins, `/strategies` and probes; the port value feeds `AUTHN_PORT`. |
| `internal.port` | `8090` | The internal listener (`POST /usernames/check`), served by the ClusterIP Service `<release>-internal`; feeds `AUTHN_INTERNAL_PORT`. Never route it publicly. |
| `exactUsernames.enabled` | `false` | Exact session-Secret names ([#140](https://github.com/krateo-platformops/authn/issues/140)) and the identity keys ([#144](https://github.com/krateo-platformops/authn/issues/144)); feeds `AUTHN_EXACT_USERNAMES` (`"true"`/`"false"`). On, a session Secret is `<username>-clientconfig` exactly (an identity source's name that can't be is refused, `name_not_issued`), is read exact-then-legacy with an ownership check, and every Secret authn writes carries `authn.krateo.io/username` and the labels `authn.krateo.io/principal` and `authn.krateo.io/username-label`, which a startup backfill stamps where absent. **Turn it on for a cluster only once** snowplow's exact-then-legacy reader (snowplow#1382) is rolled out there **and** the Kyverno tenant handover is done (`tenant-namespace-on-login` deleted, acmp's tenant-policy design §3.2 step 3). installer sets it per cluster. With it on, authn refuses to start unless `AUTHN_USERNAME` is already lowercase `[-a-z0-9]` of at most 63 characters (the default `authn` is). Don't also set `env.AUTHN_EXACT_USERNAMES`: the chart fails to render, naming the value to set. Adding this chart version renders the new ConfigMap key even with the flag off, which changes `checksum/configmap` and rolls the pod once. See [behavior](./behavior.md#exact-session-secret-names-exactusernames). |
| `replicaCount` | `1` | With `autoscaling.enabled: false` (default). |
| `livenessProbe` / `readinessProbe` | `GET /health` | `/health` flips 200 once the listener goroutine starts, 503 on shutdown — process lifecycle only ([gotchas](./gotchas.md)). |
| `ingress` | `enabled: false` | Standard chart ingress if you need it. |
| `jwt.signKeySecretName` / `jwt.signKeySecretKey` | `authn-jwt-signing-key` / `private.pem` | Secret holding the PEM-encoded RSA private key, mounted as a file. |
| `jwt.kid` | `krateo-authn-key-1` | Key ID (`kid`) stamped into every token header and the JWKS ([jwt-jwks](./jwt-jwks.md)). |
| `jwt.previousKeys` | `[]` | Keys retired by a rotation: `{kid, secretName, secretKey}` (default `private.pem`). Published in the JWKS for verification only, never used to sign ([jwt-jwks](./jwt-jwks.md#rotating-the-signing-key)). |
| `serviceAccount.create` | `true` | The SA the CSR/TokenReview ClusterRoles bind to. |
| `env.*` | see below | Rendered into the ConfigMap. |

## `env.*` — the runtime knobs

Chart defaults first, then the env vars the binary reads beyond what the chart sets
(all fallbacks of flags in `go/authn/main.go`):

| Env var | Default | Effect |
|---|---|---|
| `AUTHN_KUBECONFIG_SERVER_URL` | chart: `https://kube-apiserver:6443` | The apiserver URL written into every generated kubeconfig — **set it to a reachable endpoint**. |
| `AUTHN_KUBECONFIG_CLUSTER_NAME` | `krateo` | Cluster name in the generated kubeconfig. |
| `AUTHN_KUBECONFIG_CRT_EXPIRES_IN` | `24h` | Requested lifetime of a login's client certificate, and of its JWT. The JWT is clamped to the certificate's **granted** `NotAfter`, so a signer that grants less ends the session early ([certificate-renewal](./certificate-renewal.md)). |
| `AUTHN_SERVICE_CRT_EXPIRES_IN` | `8760h` | Requested lifetime of authn's own certificate (`authn-clientconfig`). |
| `AUTHN_CRT_RENEWAL_THRESHOLD` | `0.66` | Fraction of the granted lifetime after which authn's own certificate is re-issued (0 < x < 1). |
| `AUTHN_CRT_RENEWAL_ENABLED` | `true` | Background renewal of authn's own certificate; `false` lets it expire until a restart. |
| `AUTHN_CORS` | `true` | Permissive `*`-origin CORS for the browser hop (allows `X-Auth-Code`, `X-Code-Verifier` + W3C trace-context headers). |
| `AUTHN_DEBUG` | `false` | Debug-level logging, which includes each OIDC and OAuth sign-in's name, username, email, groups and avatar URL, and the values a RESTAction adds. Don't leave it on in production. |
| `AUTHN_PORT` | `8082` (chart sets = `service.port`) | Listen port. |
| `AUTHN_INTERNAL_PORT` | `8090` (chart sets = `internal.port`) | Internal listener port, for in-cluster callers only. authn refuses to start when it equals `AUTHN_PORT`. |
| `AUTHN_NAMESPACE` | chart: release namespace | Where generated `AuthInfo` Secrets are stored. |
| `POD_NAMESPACE` | chart: release namespace | The operator namespace — **all config CRs are resolved here**. |
| `AUTHN_USERNAME` | `authn` | The service's own identity for calling snowplow RESTActions. |
| `AUTHN_SERVICEACCOUNT_AUDIENCE` | `authn` | Audience the projected SA token must carry for `/serviceaccount/login`. |
| `JWT_SIGN_KEY_FILE` | (mounted from the Secret) | Path to the PEM-encoded RSA private key; without a valid one authn exits at boot ([gotchas](./gotchas.md)). |
| `JWT_KID` | (from `jwt.kid`) | Key ID stamped into every token header and the JWKS; required, non-empty. |
| `JWT_PREVIOUS_KEYS` | (from `jwt.previousKeys`) | Verification-only keys: comma-separated `kid=path`, each a PEM RSA private or public key. An unusable entry makes authn exit at boot. |
| `SNOWPLOW_SERVICE_HOST` / `SNOWPLOW_SERVICE_PORT` | unset / `8081` | Preferred snowplow endpoint source; beware the resolution quirk ([gotchas](./gotchas.md)). |
| `URL_SNOWPLOW` | `http://snowplow.krateo-system.svc.cluster.local:8081` | Fallback snowplow URL when the SERVICE_HOST pair is unset. |
| `OTEL_ENABLED` | `false`; chart: `"true"` | Master OpenTelemetry gate; tracing, metrics and audit logs each default to it. |
| `OTEL_TRACING_ENABLED` / `OTEL_METRICS_ENABLED` | = `OTEL_ENABLED` | Per-signal overrides (`go/authn/internal/telemetry/telemetry.go:36-44`). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (SDK standard); chart: `otel.endpoint`, `http://$(HOST_IP):4318` | OTLP/HTTP collector endpoint for every signal: the node-local collector agent, whose `logs/audit` pipeline writes `krateo_audit`. `HOST_IP` comes from `status.hostIP`. |
| `OTEL_LOGS_ENABLED` | = `OTEL_ENABLED` | Sends audit records over OTLP logs (AUDIT-4). Off: no record is written, and authn reads nothing extra. |
| `POD_SERVICE_ACCOUNT` | chart: authn's ServiceAccount | The actor of the audit records of authn's own background writes. Required when `OTEL_LOGS_ENABLED` is true; authn exits at boot without it. |

Flags mirror all of the above (`--port`, `--cert-expires`, `--jwt-sign-key-file`,
`--jwt-kid`, `--jwt-previous-keys`, `--serviceaccount-audience`, `--service-cert-expires`,
`--cert-renewal`, `--cert-renewal-threshold`, `--otel-tracing`, `--kubeconfig` for
out-of-cluster runs, …) — flags win over env ([architecture](./architecture.md)).

## The CRDs chart

`authn-crds` ([`helm/authn-crds/`](../helm/authn-crds/)) has no configuration: it
installs the five `*.authn.krateo.io` CRDs ([api](./api.md)). It is deliberately
**not** a dependency of the app chart, so CRD ownership stays with its own release.
The CRDs are chart **templates**, not files in the chart's `crds/` directory, so
`helm show crds` prints nothing and Helm upgrades them like any other resource. To
inspect a version's schema, render it:
`helm template x oci://ghcr.io/krateo-platformops/charts/authn-crds --version X.Y.Z`.
