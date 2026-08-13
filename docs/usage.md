---
type: Usage
title: authn — usage
description: How authn is installed — via the Krateo installer component pin, or directly from the OCI chart — and its install-time dependencies.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [install, helm, installer]
timestamp: 2026-08-07T00:00:00Z
---

# Usage

authn ships as two Helm charts from this monorepo, published by CI to GHCR at the
**same version = the repo tag** (see [release](./release.md)):

| Artifact | Where |
|---|---|
| App chart | `oci://ghcr.io/krateo-platformops/charts/authn` |
| CRDs chart (`User`, `ServiceAccount`, `LDAPConfig`, `OAuthConfig`, `OIDCConfig`) | `oci://ghcr.io/krateo-platformops/charts/authn-crds` |
| Image (multi-arch) | `ghcr.io/krateo-platformops/authn` |

## Path 1 — via the Krateo installer (the normal way)

authn is a core component of the Krateo installer: the installer umbrella pins the
chart URL + version and reconciles authn (and `authn-crds`) as Compositions. A
platform install gets authn with no extra steps; a version bump is a change to the
installer's pin.

Standalone of the installer, the same mechanism is a raw `CompositionDefinition`
(requires core-provider), as in
[`compositiondefinition.yaml`](../compositiondefinition.yaml) — note the committed
sample pins an older chart version; set the version you mean to run:

```yaml
apiVersion: core.krateo.io/v1alpha1
kind: CompositionDefinition
metadata:
  name: krateo-authn
  namespace: krateo-system
spec:
  chart:
    url: oci://ghcr.io/krateo-platformops/charts/authn
    version: "0.26.0"
```

## Path 2 — direct `helm install`

```sh
# CRDs first:
helm install authn-crds oci://ghcr.io/krateo-platformops/charts/authn-crds --version 0.26.0

# The JWT signing-key Secret (hard dependency, see below) — a PEM-encoded RSA
# private key, not a shared secret:
openssl genrsa -out private.pem 2048
kubectl create secret generic authn-jwt-signing-key -n krateo-system \
  --from-file=private.pem=./private.pem

# The app chart:
helm install authn oci://ghcr.io/krateo-platformops/charts/authn \
  --version 0.26.0 --namespace krateo-system
```

### Install-time dependencies

- **The JWT signing-key Secret** — the Deployment mounts, as a file, the Secret named
  by `jwt.signKeySecretName` (default `authn-jwt-signing-key`, key `jwt.signKeySecretKey` /
  `private.pem`); the pod does not start without it. authn signs asymmetrically
  (RS256) and publishes the matching **public** key at `/.well-known/jwks.json` — see
  [jwt-jwks](./jwt-jwks.md) for how validators (snowplow, agentgateway) consume it.
- **CRDs before the app** — the app only *reads* the five `*.authn.krateo.io` CRDs
  at request time, so a missing CRD does not block startup, but every login of that
  strategy fails until its CRD (and a config CR) exists. Install `authn-crds` first.
- **`AUTHN_KUBECONFIG_SERVER_URL`** — the chart default (`https://kube-apiserver:6443`)
  is a placeholder; set it to the apiserver endpoint your users can actually reach,
  or every generated kubeconfig points nowhere ([configuration](./configuration.md)).

### RBAC the chart installs (and why)

The chart binds authn's ServiceAccount to broad **CSR** permissions
(create/get/list/watch/delete/update/approve on `certificatesigningrequests` +
`approve` on signer `kubernetes.io/kube-apiserver-client`) — every login mints and
self-approves a client cert. It also grants `create` on
`tokenreviews.authentication.k8s.io` and read on
`serviceaccounts.serviceaccount.authn.krateo.io` for the intra-service strategy, and
a namespaced Role over Secrets/ConfigMaps and the config CRDs. Details:
[gotchas](./gotchas.md).

## Config CRs — where they must live

authn resolves every config CR (`User`, `ServiceAccount` mappings, `LDAPConfig`,
`OAuthConfig`, `OIDCConfig`) **in its own operator namespace** (from `POD_NAMESPACE`,
set by the chart to the release namespace). A CR created elsewhere is invisible.
See the [examples](./examples.md).

## Rendering the chart locally

The in-repo `Chart.yaml` carries `CHART_VERSION` / `APP_VERSION` placeholders that CI
substitutes at release time, so substitute them before a local render (exactly what
the lint workflow does):

```sh
sed -i.bak 's/CHART_VERSION/0.0.0/g; s/APP_VERSION/0.0.0/g' helm/authn/Chart.yaml
helm template authn helm/authn
git checkout helm/authn/Chart.yaml && rm -f helm/authn/Chart.yaml.bak
```

## Calling it

The frontend drives logins via `GET /strategies`; every strategy's request shape and
the common response contract are in [api](./api.md) and worked end-to-end in the
[examples](./examples.md).
