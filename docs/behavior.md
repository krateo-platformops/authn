---
type: API
title: authn — runtime behavior (internals)
description: The HTTP endpoints the running service exposes, the five CRDs it reads, the login/response contract and its integration contracts — traced to file:line.
resource: ghcr.io/krateo-platformops/authn
tags: [internals, http, crd, code-traced]
timestamp: 2026-08-07T00:00:00Z
---

# authn — runtime behavior

What the running service exposes and the contracts it depends on (paths relative to
`go/authn/`). All paths are **literal** (exact match, see
[architecture.md](./architecture.md)); the default listen port is `8082`
(`AUTHN_PORT`, `main.go:55`).

## HTTP endpoints

Every route is registered in `main.go:169-233` and implements `routes.Route`.

| Method | Path            | Purpose | Source |
| ------ | --------------- | ------- | ------ |
| GET    | `/strategies`   | List configured login strategies (for the frontend login page) | `internal/routes/auth/strategies/strategies.go` |
| GET    | `/info`         | Fetch a stored `AuthInfo` by `?name=` | `internal/routes/auth/info/info.go` |
| GET    | `/health`       | Liveness/readiness; returns `{name,version}` once healthy, else `503` | `internal/routes/health/health.go` |
| GET    | `/.well-known/jwks.json` | Public key set for verifying authn's RS256 JWTs ([jwt-jwks](./jwt-jwks.md)) | `internal/routes/jwks/jwks.go` |
| GET    | `/basic/login`  | HTTP Basic login → kubeconfig (+JWT) | `internal/routes/auth/basic/login.go` |
| POST   | `/serviceaccount/login` | Kubernetes intra-service auth: SA token (TokenReview) → kubeconfig (+JWT) | `internal/routes/auth/serviceaccount/login.go` |
| POST   | `/ldap/login`   | LDAP login (JSON body) → kubeconfig (+JWT) | `internal/routes/auth/ldap/login.go` |
| GET    | `/oauth/login`  | OAuth2 code exchange → kubeconfig (+JWT) | `internal/routes/auth/oauth/login.go` |
| GET    | `/oidc/login`   | OIDC code exchange → kubeconfig (+JWT) | `internal/routes/auth/oidc/login.go` |

Note: `internal/routes/list.go` defines a `/list` route (OAuthConfigs only), but it
is **not registered** in `main.go` and so is not served at this tag.

### `/strategies`

Returns a JSON array of `{kind, name?, graphics?, path, extensions?}`
(`strategies.go:191-197`).
- `basic` appears **only if at least one `User` CR exists** (`strategies.go:58-64`).
- `oidc`/`ldap`/`oauth` produce one entry per CR. Missing `graphics` is filled with a
  default (`key` icon, "Login with <Kind>", white/black, `support.go:12-19`).
- `oidc` and `oauth` entries carry `extensions.authCodeURL` / `extensions.redirectURL`
  so the frontend can start the provider redirect (`strategies.go:122-131`,
  `177-186`).

### The login response contract

All five login routes converge on `encode.Success` (`encode/success.go:18-53`) and
return:

```json
{
  "accessToken": "<JWT, omitted if no signing key>",
  "user":   { "displayName": "...", "username": "...", "avatarURL": "..." },
  "groups": ["..."],
  "data":   <base64-free JSON kubeconfig (Kind: Config)>
}
```

- `data` is the per-user kubeconfig minted by the generator (`config/build.go:115-147`).
- `accessToken` is always present — authn fails to boot without a valid signing key; the JWT duration is the
  cert-duration knob, with an 8h default if no explicit duration
  (`success.go:32-46`).
- `/basic/login?d` instead returns the kubeconfig as a file download
  (`Content-Disposition`, `basic/login.go:94-96` → `encode/attach.go`).

### Login inputs per strategy

- **basic** — HTTP `Authorization: Basic` header; `401` with `WWW-Authenticate` if
  absent (`basic/login.go:65-70`). Password compared in plaintext against the Secret
  keyed by `User.spec.passwordRef` (`basic/login.go:107-125`).
- **serviceaccount** — HTTP `Authorization: Bearer <projected SA token>`; `401` with
  `WWW-Authenticate: Bearer` if absent (`serviceaccount/login.go:76-81`). The token
  is validated via the Kubernetes `TokenReview` API: authn submits it with the
  expected audience (default `authn`, `--serviceaccount-audience` /
  `AUTHN_SERVICEACCOUNT_AUDIENCE`) and requires `status.authenticated == true`
  **and** the audience to be echoed back (`serviceaccount/login.go:118-136`). It then
  parses the authenticated `system:serviceaccount:<ns>:<name>` username and looks up
  a `ServiceAccount` mapping whose `spec.serviceAccountRef` matches that SA, **in the
  authn operator namespace** (`resolvers.ServiceAccountForSA`). No mapping → `403`
  (the allowlist); an SA matched by more than one mapping → error (ambiguous). On
  success authn issues the standard kubeconfig + JWT with username = the mapping's
  `metadata.name`, groups = `spec.groups`, and `displayName` from the mapping. Any
  TokenReview/validation/mapping failure returns `403` (`encode.Forbidden`,
  `serviceaccount/login.go:83-88`).
- **ldap** — `?name=<LDAPConfig>` + JSON body `{"username","password"}`
  (`ldap/login.go:73-130`). Error mapping: not-found → `404`, multiple entries →
  `300`, other → `403` (`ldap/login.go:102-110`).
- **oauth** — `?name=<OAuthConfig>` + `X-Auth-Code` header (`oauth/login.go:73-90`).
  Code is exchanged via `golang.org/x/oauth2` (`oauth/login.go:106`); token type must
  be `bearer` when a RESTAction is configured (`oauth/login.go:116-121`).
- **oidc** — `?name=<OIDCConfig>` + `X-Auth-Code` header. Code is POSTed to the token
  endpoint; ID-token claims (`preferred_username`, `name`, `picture`, `email`,
  `groups`) are read, and the UserInfo endpoint is called only for the claims the ID
  token omits (`oidc/support.go:112-208`). `groups` is never sourced from UserInfo
  (`oidc/support.go:149-156`).

## CRDs it reads

authn owns five namespaced CRDs (group `*.authn.krateo.io`, version `v1alpha1`),
rendered under `crds/`. It only **reads** them at request time — there is no
controller that writes status — and it resolves them **in its operator namespace**
(`POD_NAMESPACE`, `internal/helpers/kube/util/util.go:23-38`).

### `User` (`basic.authn.krateo.io`) — `apis/authn/basic/v1alpha1/types.go`
- `spec.passwordRef` (`SecretKeySelector`, required) — Secret holding the password.
- `spec.displayName`, `spec.avatarURL` (both required by the CRD schema),
  `spec.groups[]` (optional).

### `ServiceAccount` (`serviceaccount.authn.krateo.io`) — `apis/authn/serviceaccount/v1alpha1/types.go`
The intra-service-auth exchange allowlist; `metadata.name` is the issued username
(like `User`).
- `spec.serviceAccountRef` (`ObjectRef {namespace,name}`, required) — the Kubernetes
  ServiceAccount allowed to exchange its (audience-bound) token for this identity.
  The CR's existence is the allowlist: an SA with no matching CR cannot exchange.
- `spec.groups[]` (optional) — become the issued cert's `O=`, so standard Kubernetes
  RBAC bound to these groups scopes the identity; authn never authors RBAC.
- `spec.displayName` (optional).

  authn looks these up by **listing the operator namespace** and matching
  `serviceAccountRef` (`resolvers.ServiceAccountForSA`), not by name — a mapping's
  name is the issued username and need not equal the SA name.

### `LDAPConfig` (`ldap.authn.krateo.io`) — `apis/authn/ldap/v1alpha1/types.go`
- `spec.dialURL` (required), `spec.baseDN` (required).
- `spec.bindDN` + `spec.bindSecret` (optional; omit for anonymous bind).
- `spec.tls` (optional bool — `StartTLS` with `InsecureSkipVerify`, see
  [gotchas.md](./gotchas.md)).
- `spec.graphics` (optional).

### `OIDCConfig` (`oidc.authn.krateo.io`) — `apis/authn/oidc/v1alpha1/types.go`
- `spec.clientID`, `spec.clientSecret` (`SecretKeySelector`), `spec.redirectURI`.
- `spec.discoveryURL`, `spec.authorizationURL`, `spec.tokenURL`, `spec.userInfoURL`,
  `spec.additionalScopes`.
- `spec.restActionRef` (optional `ObjectRef` — enrich the identity via snowplow).
- `spec.graphics` (optional).

### `OAuthConfig` (`oauth.authn.krateo.io`) — `apis/authn/oauth/v1alpha1/types.go`
- Inlines the base `ConfigSpec` (`apis/authn/oauth/types.go`): `spec.clientID`,
  `spec.clientSecretRef`, `spec.authURL`, `spec.tokenURL`, `spec.redirectURL`,
  `spec.scopes[]`, `spec.authStyle` (optional int; `0` = auto-detect how creds are
  sent).
- Adds `spec.restActionRef` (functionally required — OAuth2 returns no user info, the
  RESTAction compiles the identity) and `spec.graphics` (optional)
  (`v1alpha1/types.go:9-14`).

Shared types (`Graphics`, `ObjectRef`, `SecretKeySelector`) — `apis/core/core.go`.

## Integration contracts

### Kubernetes CSR API (the cluster)
On every successful login the generator creates a `CertificateSigningRequest` with
signer `kubernetes.io/kube-apiserver-client` and **self-approves it**
(`config/gen.go:36-68`, `certs.go:171-173`). This requires the broad CSR RBAC the
chart installs (create / get / list / watch / approve / delete / update on
`certificatesigningrequests`, plus `approve` on the signer — see
`helm/authn/templates/clusterrole.yaml`; `manifests/rbac.csr.yaml` is the dev-cluster
equivalent). The minted cert's CN = username and O = groups become the caller's
Kubernetes identity.

### Kubernetes TokenReview API (intra-service auth)
The `/serviceaccount/login` strategy validates the caller's projected ServiceAccount
token by creating a `TokenReview` (`authentication.k8s.io`) with the expected
audience and reading back `status.authenticated` / `status.user.username` /
`status.audiences` (`serviceaccount/login.go:118-136`). This requires authn's
ServiceAccount to be granted `create` on `tokenreviews.authentication.k8s.io` (in
addition to the CSR RBAC above); without it every intra-service login fails at the
TokenReview call.

### snowplow (identity enrichment)
When an `OIDCConfig`/`OAuthConfig` has a `restActionRef`, authn enriches the identity
by calling snowplow's `/call` endpoint for that RESTAction
(`internal/helpers/restaction/resolver.go:26-66`), authenticating with the long-lived
`authn` service JWT (`main.go:195-203`). Two resolution paths:
- **`Resolve`** — calls the RESTAction directly, passing the user's bearer token as
  an `extras` param (`resolver.go:26-66`).
- **`LegacyResolve`** — fallback used when `Resolve` doesn't return a usable `name`:
  it deep-copies the RESTAction + its endpoint Secrets per-user, calls it, then
  deletes the copies (`resolver.go:68-186`). The returned `status` map may override
  `name`, `email`, `preferredUsername`, `groups`, `avatarURL`
  (`oidc/support.go:233-280`); any other key is rejected (`checkKeys` default case,
  `oidc/support.go:317-319`).

The snowplow base URL comes from `SNOWPLOW_SERVICE_HOST`/`SNOWPLOW_SERVICE_PORT` or
`URL_SNOWPLOW` (default `http://snowplow.krateo-system.svc.cluster.local:8081`,
`main.go:63-72`).

### Stored AuthInfo (the `/info` endpoint)
Each `Generate` persists an `AuthInfo` (cert/key/CA/server) via the storage layer —
a Secret per identity (`config/build.go:150-160`,
`config/storage/storage.go:47-74`); `/info?name=` reads it back (`info/info.go:45-80`).
`name` is required (`400` otherwise).

### Frontend
The frontend consumes `/strategies` to render the login page and the login response
(`data` + `accessToken`) to authenticate the user. CORS is enabled by default with
`*` origin; the allowed headers include the custom `X-Auth-Code` plus the W3C
trace-context headers `traceparent`/`tracestate`/`baggage` (`main.go:257-270`).
