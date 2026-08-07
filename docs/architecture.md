---
type: Architecture
title: authn — architecture (internals)
description: How the service is built — main.go boot, the route table, the Route interface, the kubeconfig generator and the five auth packages — traced to file:line.
resource: ghcr.io/krateo-platformops/authn
tags: [internals, code-traced]
timestamp: 2026-08-07T00:00:00Z
---

# authn — architecture

How the service is built, traced to the current tree (paths relative to `go/authn/`).
authn is a single Go binary (`main.go`): a stateless HTTP server with one in-process
route table, no database, and no controller loop. It reads configuration CRDs from the
apiserver on each request and mints client-cert kubeconfigs through the Kubernetes CSR
API.

> Read this as a map. Every claim cites `file:line` in this repo at this tag. If a
> README or note disagrees with the code, the code wins.

## Entry point — `main.go`

`main()` (`main.go:47`) does, in order:

1. **Flags + env.** Every flag has an env fallback via `internal/env` (`main.go:49-80`):
   port (`AUTHN_PORT`, default `8082`, `main.go:55`), CORS toggle (`AUTHN_CORS`,
   default on, `main.go:52`), OTel tracing toggle (`--otel-tracing`, default
   `OTEL_TRACING_ENABLED` → `OTEL_ENABLED`, `main.go:53-54`), generated-cert duration
   (`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`, default `24h`, `main.go:56-57`), cluster name
   (`main.go:59-60`), apiserver URL for the generated kubeconfig (`main.go:61-62`),
   the snowplow URL for RESTAction calls (`main.go:63-72`), the storage namespace
   (`AUTHN_NAMESPACE`, `main.go:73-74`), the authn service username (`AUTHN_USERNAME`,
   default `authn`, `main.go:75-76`), the JWT signing key (`JWT_SIGN_KEY`,
   `main.go:77`), and the ServiceAccount-token audience
   (`AUTHN_SERVICEACCOUNT_AUDIENCE`, default `authn`, `main.go:78-80`).
2. **Logger.** zerolog to stdout, `info` unless `--debug` (`main.go:94-105`).
3. **OpenTelemetry (default OFF).** `telemetry.Setup` initializes the gated
   traces/metrics pipelines (`main.go:135-147`); the master gate is `OTEL_ENABLED`
   with per-signal overrides (`internal/telemetry/telemetry.go:36-44`). When both
   signals are off the handler chain is left untouched.
4. **Kube rest config.** In-cluster by default, or from `--kubeconfig`
   (`main.go:149-158`).
5. **Kubeconfig generator.** `kubeconfig.NewGenerator(cfg, …)` (`main.go:160-165`) —
   the shared component every login route uses to mint a per-user kubeconfig.
6. **Route table.** A `[]routes.Route` is assembled (`main.go:169-233`): `strategies`,
   `info`, `health`, and the five login routes (`basic`, `serviceaccount`, `ldap`,
   `oauth`, `oidc`).
7. **Service JWT.** A 1-year JWT for the `authn` service identity is minted up front
   (`jwtutil.CreateToken`, `main.go:195-203`) and injected into the context the
   `oauth`/`oidc` routes use to call snowplow (`main.go:205-233`).
8. **Handler + instrumentation + CORS.** `routes.Serve(all, log)` (`main.go:235`);
   when metrics/tracing are on the handler is wrapped with the metrics middleware and
   `otelhttp` (span per request, `/health` filtered out, `main.go:243-255`); if CORS
   is on, wrapped with a permissive `*`-origin handler that allows the custom
   `X-Auth-Code` header plus the W3C trace-context headers
   (`traceparent`/`tracestate`/`baggage`, `main.go:257-270`).
9. **Self-signup.** `signup.Do(...)` (`main.go:290-299`) creates an authn
   ClientConfig so authn can call snowplow's RESTActions as itself.
10. **Serve + graceful shutdown.** `http.Server` with read/write/idle timeouts
    (`main.go:272-278`), served in a goroutine that flips the `healthy` flag
    (`main.go:301-306`); SIGINT/SIGTERM trigger a 30s graceful `Shutdown` that also
    flushes the OTel providers (`main.go:280-331`).

`Version` and `Build` are `-ldflags`-injected package vars (`main.go:42-45`), surfaced
on `/health`.

## The route model — `internal/routes`

The whole HTTP surface is a tiny hand-rolled router, not a framework.

- **`Route` interface** (`internal/routes/routes.go:11-16`): `Name()`, `Pattern()`,
  `Method()`, `Handler()`. Every endpoint is a struct implementing it.
- **`Serve`** (`internal/routes/routes.go:18-55`): exact-path match on
  `req.URL.Path == route.Pattern()` (`routes.go:22`); if the path matches but the
  method doesn't, it collects the allowed methods and returns `405` with an `Allow`
  header (`routes.go:47-51`); otherwise `404`. There is **no path templating and no
  prefix matching** — paths are literal strings. When a trace is active, the
  per-request logger is enriched with `trace_id`/`span_id` (`routes.go:31-42`); with
  tracing off the log output is byte-identical to the un-instrumented service.

Each handler is self-contained: it builds its own dynamic/typed client from the
`*rest.Config`, resolves its CRD, and writes JSON through `internal/helpers/encode`.

## The auth packages — `internal/routes/auth/*`

Five login strategies, one package each, all returning a `routes.Route`:

- **basic** (`internal/routes/auth/basic/login.go`): `GET /basic/login`. Reads HTTP
  Basic creds (`login.go:65`), looks up a `User` CR, compares the password against
  the referenced Secret (`validate`, `login.go:107-134`).
- **serviceaccount** (`internal/routes/auth/serviceaccount/login.go`):
  `POST /serviceaccount/login`. Kubernetes intra-service auth — a backend service
  authenticates with its **own** projected ServiceAccount token instead of a human
  credential. It reads the `Authorization: Bearer` token (`bearerToken`,
  `login.go:155-162`), validates it through the Kubernetes **`TokenReview` API**
  (`authentication.k8s.io`) with the expected audience (default `authn`,
  `--serviceaccount-audience`) (`validate`, `login.go:112-153`), parses the
  authenticated `system:serviceaccount:<ns>:<name>` username
  (`parseServiceAccountUsername`, `login.go:175-185`), then resolves a
  `ServiceAccount` mapping whose `serviceAccountRef` matches — the mapping is the
  **exchange allowlist**, an unmatched SA is rejected
  (`resolvers.ServiceAccountForSA`, `internal/helpers/kube/resolvers/serviceaccount.go`).
  On a hit it issues the SAME JWT + clientconfig as the other strategies, with
  username = the mapping's `metadata.name` and groups = the mapping's `spec.groups`.
  Not surfaced by `/strategies` (it has no CRD-driven login button — it is
  machine-to-machine).
- **ldap** (`internal/routes/auth/ldap/login.go`): `POST /ldap/login`. JSON body
  `{username,password}` (`loginInfo`, `login.go:127-130`); binds + searches the LDAP
  server (`support.go:60` `doLogin`).
- **oauth** (`internal/routes/auth/oauth/login.go`): `GET /oauth/login`. Exchanges
  the `X-Auth-Code` header for a token via `golang.org/x/oauth2` (`login.go:106`),
  and compiles the user identity via a snowplow RESTAction when the config carries a
  `restActionRef` (`login.go:115-141`).
- **oidc** (`internal/routes/auth/oidc/login.go`): `GET /oidc/login`. Exchanges the
  code at the token endpoint, decodes the ID token's claims, falls back to the
  UserInfo endpoint for missing claims (`support.go:79-208` `doLogin`), optionally
  enriches via RESTAction.

**strategies** (`internal/routes/auth/strategies/strategies.go`): `GET /strategies`
enumerates which strategies are configured by listing the CRDs — basic appears only
if ≥1 `User` exists (`strategies.go:58-64`); each `LDAPConfig`/`OAuthConfig`/
`OIDCConfig` becomes an entry with default `Graphics` filled in (`support.go:12-19`)
when the CR omits them.

## The kubeconfig generator — `internal/helpers/kube/config`

The common back-end of every successful login.

- **`Generate(user)`** (`build.go:96-148`): resolves the cluster CA from a ConfigMap
  if not set (`build.go:97-103`), generates the client cert/key (below), persists an
  `AuthInfo` to storage (`build.go:150-160`), and marshals a `Kind: Config`
  kubeconfig JSON (`build.go:115-147`).
- **`generateClientCertAndKey`** (`gen.go:24-85`): builds a CSR
  (`kube.NewCertificateRequest` with username as CN and groups as O), creates the
  Kubernetes `CertificateSigningRequest` (`gen.go:36-39`), **auto-approves it**
  (`gen.go:60`), waits for the signed cert (`gen.go:68`), and base64-encodes cert +
  PKCS#1 key. If a CSR with the same name already exists it is **deleted and
  recreated** (`gen.go:41-55`).
- **Signer/usages** (`internal/helpers/kube/certs.go:171-173`): signer
  `kubernetes.io/kube-apiserver-client`, usage `client auth`, with an explicit
  `ExpirationSeconds`. This is why authn needs broad CSR RBAC (see
  `manifests/rbac.csr.yaml` and the chart's ClusterRole).

The generated cert's CN/O become the Kubernetes identity the frontend then uses; RBAC
is enforced later by the apiserver, not by authn.

## The response encoder + JWT — `internal/helpers/encode`

`encode.Success` (`success.go:18-53`) wraps the kubeconfig bytes in
`{accessToken,user,groups,data}` and, when a `JwtSingKey` is configured, mints a JWT
via `plumbing/jwtutil` (default 8h if no duration, `success.go:32-46`).
`encode.Attach` (`attach.go`) instead streams the kubeconfig as a file download when
the basic route is called with `?d` (`basic/login.go:94-96`).

## API types & CRDs — `apis/`

Five CRD groups under `authn.krateo.io` (`apis/authn/*`), each with a `v1alpha1`
package and generated `zz_generated.deepcopy.go`:

- `basic.authn.krateo.io` → `User` (`apis/authn/basic/v1alpha1/types.go`)
- `serviceaccount.authn.krateo.io` → `ServiceAccount`
  (`apis/authn/serviceaccount/v1alpha1/types.go`) — the intra-service-auth exchange
  allowlist: `serviceAccountRef {namespace,name}` (the k8s SA allowed to exchange),
  `groups[]` (→ issued cert `O=` → k8s RBAC), `displayName`.
- `ldap.authn.krateo.io` → `LDAPConfig` (`apis/authn/ldap/v1alpha1/types.go`)
- `oidc.authn.krateo.io` → `OIDCConfig` (`apis/authn/oidc/v1alpha1/types.go`)
- `oauth.authn.krateo.io` → `OAuthConfig` (`apis/authn/oauth/v1alpha1/types.go`,
  which inlines the base `ConfigSpec` from `apis/authn/oauth/types.go` and adds
  `restActionRef` + `graphics`)

Shared field types (`Graphics`, `ObjectRef`, `SecretKeySelector`) live in
`apis/core/core.go`. The rendered manifests are committed under `crds/` and shipped
by the `authn-crds` chart. See [behavior.md](./behavior.md) for the field-level
contract.

## Dependencies on other Krateo components

authn is **not a standalone fork** — it composes shared Krateo libraries:
`plumbing/jwtutil` (JWTs), `plumbing/signup` (self-signup), `plumbing/context`
(access-token context), and it imports the **snowplow** RESTAction Go types directly
(`snowplow/apis/templates/v1`) to copy/resolve RESTActions
(`internal/helpers/restaction/`). RESTAction resolution is an HTTP call to snowplow's
`/call`, not an in-process operation.
