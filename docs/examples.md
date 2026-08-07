---
type: ExampleIndex
title: authn — examples
description: Runnable examples under examples/, each paired with a README stating preconditions and the one apply command.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [examples, login, serviceaccount]
timestamp: 2026-08-07T00:00:00Z
---

# Examples

Each example is a runnable manifest + a README with preconditions and the one
`kubectl apply` command. Both work against a stock Krateo installer deploy (authn in
`krateo-system` — the config CRs must live in authn's operator namespace,
[usage](./usage.md)).

- [basic-user](../examples/basic-user/README.md) — the smallest useful login setup: a
  `User` CR + password Secret enabling the `basic` strategy; log in with one `curl`
  and get back a kubeconfig + JWT.
- [serviceaccount-mapping](../examples/serviceaccount-mapping/README.md) — Kubernetes
  intra-service auth: a `ServiceAccount` allowlist mapping that lets a backend
  service exchange its own projected (audience-bound) SA token for a Krateo identity.

More strategy configurations (LDAP, OAuth2/GitHub, OIDC/Azure — including
RESTAction-based group enrichment with pagination) live as developer test fixtures
under [`go/authn/testdata/`](../go/authn/testdata/); they show real field shapes but
carry placeholder endpoints/credentials you must substitute.
