---
type: Architecture
title: authn — overview
description: What authn is (the Krateo authentication service), how a login becomes a client-cert kubeconfig + JWT, and where it sits in the platform.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [authn, authentication, csr, jwt, strategies]
timestamp: 2026-08-07T00:00:00Z
---

# Overview

authn is the **authentication service of the Krateo platform**: it converts a
successful login into a Kubernetes identity. Whatever the strategy, the output is the
same — a short-lived, per-user **client-certificate kubeconfig** minted through the
Kubernetes CSR API (cert `CN=username, O=groups`) plus a **JWT** signed
asymmetrically (RS256) with authn's own RSA private key; the matching public key is
published as a JWKS at `/.well-known/jwks.json` ([jwt-jwks](./jwt-jwks.md)). authn
authenticates; it never authorizes — RBAC on
the minted identity is enforced by the apiserver via standard bindings on the cert's
groups.

The code-traced internals map is [architecture.md](./architecture.md); the runtime
contract is [behavior.md](./behavior.md). This page is the distilled platform view.

## What it does

- **Serves five login strategies**, one package each, converging on one response
  shape ([api](./api.md)):
  - `basic` — HTTP Basic against a `User` CR + password Secret;
  - `ldap` — bind + search against an `LDAPConfig`-described server;
  - `oauth` — authorization-code exchange per `OAuthConfig`, identity compiled by a
    snowplow RESTAction;
  - `oidc` — code exchange + ID-token claims per `OIDCConfig` (UserInfo fallback,
    optional RESTAction enrichment);
  - `serviceaccount` — **Kubernetes intra-service auth**: a backend service exchanges
    its own projected, audience-bound SA token (validated via the TokenReview API)
    against a `ServiceAccount` allowlist mapping
    ([decision](./design/kubernetes-intra-service-auth.md)).
- **Lists the configured strategies** (`GET /strategies`) so the frontend can render
  the login page — one entry per config CR, with button graphics.
- **Mints the identity**: every successful login creates a Kubernetes
  `CertificateSigningRequest` (signer `kubernetes.io/kube-apiserver-client`),
  self-approves it, and returns the signed cert inside a ready-to-use kubeconfig;
  the cert/cluster info is also persisted as a Secret and readable via `GET /info`.

## The login path

```
credential ─▶ strategy handler ─▶ config CR lookup (operator namespace)
                    │
             validate (Secret compare | LDAP bind | code exchange | TokenReview)
                    │
     kubeconfig generator: CSR create ─▶ self-approve ─▶ signed cert
                    │
   { accessToken (JWT), user, groups, data: kubeconfig } ─▶ caller
```

Configuration CRs are read from the apiserver **on each request** — there is no
controller, no cache and no state beyond the persisted `AuthInfo` Secrets.

## Where it sits in the platform

| Peer | Relationship |
|---|---|
| **frontend** | Consumes `GET /strategies` to render the login page and the login response (`data` + `accessToken`) to authenticate the user; CORS is on by default for the cross-origin browser hop. |
| **snowplow** | Two-way: authn calls snowplow's `/call` to resolve RESTActions that enrich OAuth2/OIDC identities (authenticating with its own self-minted service JWT), and snowplow validates the JWTs authn issues using authn's RSA **public** key (RS256). snowplow's prewarm seed is itself a `serviceaccount`-strategy consumer. |
| **core-provider / cdc** | Backend services use the `serviceaccount` strategy to obtain a scoped Krateo identity without holding the signing key — the exchange allowlist is the `ServiceAccount` CRD authn owns. |
| **the cluster** | The CSR API is the identity mint (broad CSR RBAC required); the TokenReview API validates intra-service SA tokens ([gotchas](./gotchas.md)). |

## Deployment shape

One Deployment, one container, one port (default `8082`) serving logins, probes and
`/strategies` alike. All configuration arrives as env vars via a chart-managed
ConfigMap plus the JWT signing-key Secret ([configuration](./configuration.md)).
OpenTelemetry traces/metrics are built in but **default off** (`OTEL_ENABLED`).
