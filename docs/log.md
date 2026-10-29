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

## 2026-10-29 — authn can run more than one replica (#45)

0.28.0 renewed `authn-clientconfig` in a loop that assumed a single replica: its CSR is
named after the username and recreated on conflict, so two replicas would delete each
other's requests.

Now only the replica holding the `authn-cert-renewal` Lease does authn's own-identity
work: issuing, renewing and the identity backfill. Every replica serves logins, so
`replicaCount > 1` and autoscaling are safe. A crashed leader is replaced within 15s.
The chart's Role gains `get/create/update` on `leases`.

## 2026-10-29 — clientconfig Secrets record their strategy and groups (#42)

Tenant onboarding (a Kyverno policy) fires on every `<user>-clientconfig` Secret, but nothing
on them told a tenant from a platform admin or from authn's own identity. So every
clientconfig authn writes now carries:
- `authn.krateo.io/strategy` (`self` for authn's own identity);
- `authn.krateo.io/groups`: the certificate's `O=`, newline-separated, because group names
  can contain commas.

A startup backfill stamps older Secrets. Groups come from the certificate; the strategy is
set only where it can be proven, otherwise it's `unknown`. The policy decides from these
facts, so there's no hand-kept list of names.

## 2026-10-29 — `/serviceaccount/login` no longer returns the kubeconfig (#36)

The serviceaccount login returned the full kubeconfig in `data`, including
`client-key-data`, a private key. The natural first step when integrating, printing the
response, wrote that key into a terminal ([#36](https://github.com/krateo-platformops/authn/issues/36)).

**The fix:** the response now carries only `accessToken`, `user` and `groups`. authn still
mints the identity and writes `<username>-clientconfig`, which plumbing endpoints,
snowplow and bff read from the Secret.

**Fleet check before the change:** across 56 repos, the four clients of this endpoint
decode `accessToken` only:
- core-provider
- core-provider's cdc
- rest-dynamic-controller
- snowplow

The human strategies are unchanged.

## 2026-10-29 — client certificates: authn's own is renewed, login JWTs are clamped (#28)

Fixes [#28](https://github.com/krateo-platformops/authn/issues/28), ported from
PR #76 of the legacy pre-fork repository (by EdmondDantes21), which never reached this repo:
- `authn-clientconfig` was written once at boot and never renewed. A pod that outlived
  its certificate failed every RESTAction call with `x509: certificate has expired`
  until restarted.
- The signer may grant far less than requested: OpenShift caps at 720h and rotates its
  CA every 30 days.

What changed:
- authn now reads the **granted** `NotAfter` and annotates every Secret with it.
- It renews its own certificate in the background at a fraction of the granted lifetime.
- Every login JWT, including `serviceaccount`, is clamped to its certificate's real
  expiry, so a session can no longer outlive its credential.
- New knobs: `AUTHN_SERVICE_CRT_EXPIRES_IN`, `AUTHN_CRT_RENEWAL_THRESHOLD`,
  `AUTHN_CRT_RENEWAL_ENABLED`.

See [certificate-renewal](./certificate-renewal.md). Verified on kind; capped-signer
distributions are still unverified.

## 2026-10-29 — intra-service auth: §6 open questions closed

The [decision record](./design/kubernetes-intra-service-auth.md) still listed token
audience & naming, JWT lifetime and the endpoint shape as open, although 0.23.0 had already
settled them. The record now matches the shipped code:
- one global audience, `authn`, configurable per install;
- the username is the mapping's `metadata.name`;
- `POST /serviceaccount/login`;
- the JWT lives as long as the client certificate (`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`), with no
  per-mapping TTL.

Revocation is mapping deletion for new exchanges, plus RBAC unbinding or expiry for
credentials already issued. Multi-cluster is decided as **target-local authn**: a service in
a remote target exchanges its token with an authn in that target, because TokenReview is
cluster-local. Bootstrap ordering is resolved as caller-side degradation, which both shipped
callers already do (core-provider's cdc and snowplow's prewarm seed). §6 is now fully closed.

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
