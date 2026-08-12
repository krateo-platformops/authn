---
type: Component
title: authn — index
description: The map of the authn doc bundle — the Krateo authentication service that turns logins into per-user client-cert kubeconfigs and JWTs.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [authn, authentication, security, identity]
timestamp: 2026-08-07T00:00:00Z
---

# authn

authn is the **authentication service of Krateo PlatformOps**: a stateless Go HTTP
server that turns a successful login — basic / LDAP / OAuth2 / OIDC, plus the
`serviceaccount` strategy for Kubernetes intra-service auth — into a short-lived,
per-user **client-cert kubeconfig** (minted via the Kubernetes CSR API) plus a JWT,
and lists the configured login strategies for the Krateo frontend. This monorepo
carries the app (`go/authn/`), its Helm charts (`helm/authn/`, `helm/authn-crds/`)
and one version line: image and charts ship together from a single plain-semver tag.

## The bundle (start here)

- [overview](./overview.md) — what it does and how it works: the five strategies, the
  CSR-minted identity, its place between frontend / snowplow / core-provider.
- [usage](./usage.md) — install via the Krateo installer pin or direct
  `helm install oci://…`; the JWT signing-key Secret hard dependency.
- [configuration](./configuration.md) — the whole config surface: values, the env
  ConfigMap contract, flags, OTel gates.
- [api](./api.md) — the five `*.authn.krateo.io` CRDs and the HTTP surface.
- [jwt-jwks](./jwt-jwks.md) — RS256 signing, the JWKS endpoint, and how Snowplow /
  agentgateway consume it.
- [rbac](./rbac.md) — how the generated client cert (CN=username, O=groups) maps to
  Kubernetes RBAC: binding roles to `User` and `Group` subjects. authn issues identity;
  RBAC authorizes it.
- [examples](./examples.md) — the runnable examples under `examples/`.
- [release](./release.md) — how a release ships (tag → image + charts on GHCR).
- [log](./log.md) — curated history.
- [llms.txt](./llms.txt) — the version-pinned agent index of this bundle.

## The internals corpus (code-traced, authoritative for internals)

Each claim in these cites `file:line` under `go/authn/` at this tag:

- [architecture.md](./architecture.md) — how the service is built: `main.go` boot,
  the route table, the `Route` interface, the kubeconfig generator, the five auth
  packages. Read first for internals.
- [behavior.md](./behavior.md) — the HTTP endpoints it serves, the five CRDs it
  reads, the login/response contract, its integration contracts (snowplow
  RESTAction, Kubernetes CSR + TokenReview).
- [gotchas.md](./gotchas.md) — real runtime pitfalls grounded in the code/config
  (RBAC traps, exact-match routing, OIDC token handling, the snowplow URL quirk).

**Decisions** ([docs/design/](./design/)) —
[kubernetes-intra-service-auth](./design/kubernetes-intra-service-auth.md)
(`status: implemented`, shipped in 0.23.0): the `serviceaccount` login strategy —
SA token → TokenReview → allowlist mapping → JWT + clientconfig.

## Reading at the right version

These docs describe a SPECIFIC build. Read them **at the tag that matches the running
image** (the authn Deployment's container image tag == the chart `appVersion` == the
repo tag; charts and image share one version line). If something is not in the docs,
read the source at that same tag — do not trust `main` for a deployed older version.
