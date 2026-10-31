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
| `oidcconfigs.oidc.authn.krateo.io` | `OIDCConfig` | An OIDC provider: `clientID`, `clientSecret`, `redirectURI`, plus `discoveryURL` and/or explicit `authorizationURL`/`tokenURL`/`userInfoURL` (discovery fills the endpoints when any is unset), and `issuer` when there is no `discoveryURL` (#50); optional `stepUp` {`acrValues`, `maxAge` (5m), `ttl` (15m)} enables `/oidc/stepup` (#49); optional `additionalScopes`, `restActionRef`, `graphics`. |

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
| GET | `/oidc/login?name=<OIDCConfig>` | `X-Auth-Code: <code>` header, plus `X-Code-Verifier: <verifier>` when the authorization request used PKCE → code exchange → ID-token claims (UserInfo fallback) → login response. |
| POST | `/oidc/stepup?name=<OIDCConfig>` | Step-up (#49). Same input as `/oidc/login`, from an authorization request with `acr_values`. If the ID token's `acr` is in `spec.stepUp.acrValues` and its `auth_time` is within `maxAge`, authn mints a `krateo:loa:2` credential into `<user>-clientconfig-stepup` and returns `accessToken` (groups include `krateo:loa:2`, expiry ≤ the certificate's), `user` and `groups`, with no `data`. The session credential is untouched. |
| POST | `/serviceaccount/login` | `Authorization: Bearer <projected SA token, audience authn>` → TokenReview → allowlist mapping → login response. |
| GET | `/info?name=<username>` | The stored `AuthInfo` (cert/key/CA/server) for a previously logged-in identity. |
| GET | `/health` | `{name,version}` once serving, `503` otherwise (process lifecycle only). |

### The login response contract

Every strategy returns the same shape:

```json
{
  "accessToken": "<RS256 JWT, kid header set — see jwt-jwks.md>",
  "user":   { "displayName": "…", "username": "…", "avatarURL": "…" },
  "groups": ["…"],
  "data":   { "kind": "Config", "…": "the per-user kubeconfig" }
}
```

`data` is a complete kubeconfig whose client certificate carries
`CN=username, O=groups`: the caller's Kubernetes identity, scoped from then on by
standard RBAC. It includes the certificate's private key (`client-key-data`), so never
log a success response.

**`POST /serviceaccount/login` returns no `data`**, only `accessToken`, `user` and
`groups`. The identity's kubeconfig is still minted and stored in the
`<username>-clientconfig` Secret, where in-cluster consumers read it. Service callers
use the JWT ([#36](https://github.com/krateo-platformops/authn/issues/36)). JWT lifetime = the cert lifetime knob
(`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`, default 24h).

### `/serviceaccount/login` failures

Every failure is a Kubernetes-style `Status`. **The status code says whose failure it
is**, so a client can classify on the code alone:

- `401`/`403`: authn refused the caller. Retrying unchanged fails again; the fix is the
  caller's token, audience or mapping.
- `500`: authn could not finish the job because one of its own dependencies failed.
  Nothing is known to be wrong with the caller, and the same request may succeed later.

The top-level `reason` stays generic (`Unauthorized`, `Forbidden`, `InternalError`). The
specific cause is a stable, machine-readable token in `details.causes[0].reason`,
mirroring Kubernetes `StatusDetails`:

```json
{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403,
 "message":"token audience mismatch (require \"authn\")",
 "details":{"causes":[{"reason":"AudienceMismatch","message":"token audience mismatch (require \"authn\")"}]}}
```

| `details.causes[0].reason` | Code | Meaning |
|---|---|---|
| `MissingBearer` | 401 | No `Authorization: Bearer` header (also sets `WWW-Authenticate`) |
| `TokenNotAuthenticated` | 403 | The apiserver did not authenticate the token; its `status.error` (e.g. invalid or expired token) is in the message |
| `AudienceMismatch` | 403 | The token isn't bound to authn's audience (default `authn`) |
| `NotAServiceAccount` | 403 | The token's user isn't `system:serviceaccount:<ns>:<name>` |
| `NoMapping` | 403 | No `ServiceAccount` mapping allowlists this SA |
| `AmbiguousMapping` | 403 | More than one mapping references this SA |
| `TokenReviewFailed` | 500 | authn could not call the TokenReview API |
| `MappingLookupFailed` | 500 | authn could not list the mappings |
| `IssuanceFailed` | 500 | The caller was authenticated and mapped, but authn could not issue its clientconfig or sign its JWT |

Values are added, never renamed, and a cause never changes its code. "authn was
unreachable" is the remaining case: no response at all.

### `/oidc/login` failures

The ID token is validated before any claim is used. Failures are `Status` bodies with
the same shape as above: `403` for a token authn won't accept (retrying the same login
fails again), and `500` for an OIDCConfig authn can't validate against.

| `details.causes[0].reason` | Code | Meaning |
|---|---|---|
| `IssuerMismatch` | 403 | `iss` isn't the expected issuer (exact match, including any trailing `/`) |
| `AudienceMismatch` | 403 | `aud` doesn't include `clientID`, or there are several audiences and `azp` isn't `clientID` |
| `TokenExpired` | 403 | `exp` is more than 1 minute in the past |
| `IDTokenInvalid` | 403 | The ID token can't be decoded, or `aud`/`exp` is missing or malformed |
| `IssuerUnknown` | 500 | The OIDCConfig has neither `discoveryURL` nor `issuer` |
| `IssuerConflict` | 500 | `spec.issuer` differs from the discovery document's `issuer` |

Other OIDC failures, such as a rejected code or an unreachable token endpoint, are still
a `500` without a cause.

### `/oidc/stepup` failures

Every `/oidc/login` failure above applies, plus:

| `details.causes[0].reason` | Code | Meaning |
|---|---|---|
| `StepUpNotEnabled` | 403 | The OIDCConfig has no `spec.stepUp` |
| `InsufficientAssurance` | 403 | The ID token's `acr` isn't in `spec.stepUp.acrValues` |
| `StaleAuthentication` | 403 | `auth_time` is missing or older than `spec.stepUp.maxAge`: re-authenticate (e.g. `prompt=login` / `max_age`) |
| `StepUpMisconfigured` | 500 | `spec.stepUp` has no `acrValues`, a non-positive `maxAge`, or a `ttl` under 10m (the CSR API's minimum) |
| `IssuanceFailed` | 500 | The step-up was proven, but the credential or its token couldn't be issued |

Full request/response semantics, per-strategy validation rules and error mapping:
[behavior.md](./behavior.md).
