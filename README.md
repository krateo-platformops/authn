# authn

The authentication service of Krateo PlatformOps: it turns a successful login
(basic / LDAP / OAuth2 / OIDC / Kubernetes ServiceAccount) into a short-lived,
per-user client-certificate kubeconfig minted via the Kubernetes CSR API, plus a JWT.

## What is this

A small stateless Go HTTP server, no database and no controller loop: it reads its
five configuration CRDs (`*.authn.krateo.io`) from the apiserver at request time,
validates the presented credential per strategy, and mints the caller a Kubernetes
identity (client cert `CN=username, O=groups`) that standard RBAC then scopes. It also
lists the configured login strategies for the Krateo frontend's login page. One
monorepo, one version line: the app (`go/authn/`) and its Helm charts (`helm/`) ship
together from a single tag. Full picture: [docs/index.md](docs/index.md).

## Install

Normally installed by the **Krateo installer**, which pins the chart. Standalone:

```sh
# CRDs first (User, ServiceAccount, LDAPConfig, OAuthConfig, OIDCConfig):
helm install authn-crds oci://ghcr.io/krateo-platformops/charts/authn-crds --version 0.26.0

# The JWT signing-key Secret the Deployment hard-requires (shared with snowplow):
kubectl create secret generic jwt-sign-key -n krateo-system \
  --from-literal=JWT_SIGN_KEY="$(openssl rand -hex 32)"

helm install authn oci://ghcr.io/krateo-platformops/charts/authn \
  --version 0.26.0 --namespace krateo-system
```

Details and dependencies: [docs/usage.md](docs/usage.md).

## Configure

See [docs/configuration.md](docs/configuration.md). Most used:

| Setting | Default | Effect |
|---|---|---|
| `env.AUTHN_KUBECONFIG_SERVER_URL` | `https://kube-apiserver:6443` | The apiserver URL written into every generated kubeconfig — set it to your cluster's reachable endpoint. |
| `env.AUTHN_KUBECONFIG_CRT_EXPIRES_IN` | `24h` | Lifetime of the minted client certificate (and the login JWT). |
| `jwtSignKeySecretName` | `jwt-sign-key` | Secret holding `JWT_SIGN_KEY`; the pod does not start without it. |

## Examples

- [examples/basic-user](examples/basic-user) — a `User` CR + password Secret enabling
  the basic strategy; log in with `curl`.
- [examples/serviceaccount-mapping](examples/serviceaccount-mapping) — a
  `ServiceAccount` allowlist CR letting a backend service exchange its own projected
  SA token for a Krateo identity.

## Docs

- [docs/index.md](docs/index.md) — the map (bundle + the internals corpus)
- [docs/overview.md](docs/overview.md) — what it does and how it works
- [docs/usage.md](docs/usage.md) — how to install / consume it
- [docs/configuration.md](docs/configuration.md) — the whole config surface
- [docs/api.md](docs/api.md) — the five CRDs + the HTTP surface
- [docs/examples.md](docs/examples.md) — examples index
- [docs/release.md](docs/release.md) — how a release ships
- [docs/log.md](docs/log.md) — curated history

Internals (code-traced): [docs/architecture.md](docs/architecture.md),
[docs/behavior.md](docs/behavior.md), [docs/gotchas.md](docs/gotchas.md).

## Develop & release

`cd go/authn && go test ./...`; local cluster workflow via `go/authn/scripts/`
(kind up/down, build, deploy, server-run). Tag `X.Y.Z` (no `v` prefix) ships the
image + both charts — release runbook: [docs/release.md](docs/release.md).
