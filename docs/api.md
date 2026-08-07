---
type: API
title: authn — API
description: The five *.authn.krateo.io CRDs authn owns and the HTTP surface it serves on its single port.
resource: serviceaccounts.serviceaccount.authn.krateo.io
tags: [crd, http, login, strategies]
timestamp: 2026-08-07T00:00:00Z
---

# API

authn exposes two contracts: the **five CRDs** it owns (its configuration surface)
and the **HTTP surface** it serves. The exhaustive, code-traced version of this page
is [behavior.md](./behavior.md); field-level pitfalls are in
[gotchas.md](./gotchas.md).

## The CRDs

Five namespaced CRD groups under `*.authn.krateo.io`, version `v1alpha1`, generated
from the Go types under [`go/authn/apis/`](../go/authn/apis/) (drift-gated in CI) and
shipped by the [`authn-crds` chart](../helm/authn-crds/templates/). authn only
**reads** them at request time — no controller, no status writes — and only **in its
operator namespace** (`POD_NAMESPACE`).

| CRD | Kind | Configures |
|---|---|---|
| `users.basic.authn.krateo.io` | `User` | A basic-auth user: `spec.passwordRef` (Secret selector, required), `displayName`, `avatarURL`, `groups[]`. `metadata.name` is the username. |
| `serviceaccounts.serviceaccount.authn.krateo.io` | `ServiceAccount` | The intra-service exchange **allowlist**: `spec.serviceAccountRef {namespace,name}` (required — the k8s SA allowed to exchange its token), `groups[]` (→ issued cert `O=`), `displayName`. `metadata.name` is the issued username. |
| `ldapconfigs.ldap.authn.krateo.io` | `LDAPConfig` | An LDAP server: `dialURL` + `baseDN` (required), optional `bindDN`/`bindSecret` (anonymous bind if omitted), `tls`, `graphics`. |
| `oauthconfigs.oauth.authn.krateo.io` | `OAuthConfig` | An OAuth2 provider: `clientID`, `clientSecretRef`, `authURL`, `tokenURL`, `redirectURL`, `scopes[]` (all required), optional `authStyle`, `restActionRef`, `graphics`. |
| `oidcconfigs.oidc.authn.krateo.io` | `OIDCConfig` | An OIDC provider: `clientID`, `clientSecret`, `redirectURI`, plus either `discoveryURL` (wins) or explicit `authorizationURL`/`tokenURL`/`userInfoURL`; optional `additionalScopes`, `restActionRef`, `graphics`. |

`graphics` (`icon`, `displayName`, `backgroundColor`, `textColor`) styles the
frontend login button; `restActionRef` points at a snowplow RESTAction that compiles
identity fields — **functionally required for OAuth2** (the token response carries no
user info), optional enrichment for OIDC.

## The HTTP surface

All paths are **literal** (exact match, no trailing slash, wrong verb → `405`);
default port `8082`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/strategies` | List configured strategies for the login page: one entry per config CR (`basic` appears only if ≥1 `User` exists), with `graphics` defaults filled and `extensions.authCodeURL`/`redirectURL` for oauth/oidc. The `serviceaccount` strategy is machine-to-machine and never listed. |
| GET | `/basic/login` | `Authorization: Basic` → login response. `?d` streams the kubeconfig as a file download instead. |
| POST | `/ldap/login?name=<LDAPConfig>` | JSON body `{"username","password"}` → login response. |
| GET | `/oauth/login?name=<OAuthConfig>` | `X-Auth-Code: <code>` header → code exchange → RESTAction-compiled identity → login response. |
| GET | `/oidc/login?name=<OIDCConfig>` | `X-Auth-Code: <code>` header → code exchange → ID-token claims (UserInfo fallback) → login response. |
| POST | `/serviceaccount/login` | `Authorization: Bearer <projected SA token, audience authn>` → TokenReview → allowlist mapping → login response. |
| GET | `/info?name=<username>` | The stored `AuthInfo` (cert/key/CA/server) for a previously logged-in identity. |
| GET | `/health` | `{name,version}` once serving, `503` otherwise (process lifecycle only). |

### The login response contract

Every strategy returns the same shape:

```json
{
  "accessToken": "<JWT — omitted when JWT_SIGN_KEY is unset>",
  "user":   { "displayName": "…", "username": "…", "avatarURL": "…" },
  "groups": ["…"],
  "data":   { "kind": "Config", "…": "the per-user kubeconfig" }
}
```

`data` is a complete kubeconfig whose client certificate carries
`CN=username, O=groups` — the caller's Kubernetes identity, scoped from then on by
standard RBAC. JWT lifetime = the cert lifetime knob
(`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`, default 24h).

Full request/response semantics, per-strategy validation rules and error mapping:
[behavior.md](./behavior.md).
