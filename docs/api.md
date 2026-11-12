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
| `serviceaccounts.serviceaccount.authn.krateo.io` | `ServiceAccount` | The intra-service exchange **allowlist**: `spec.serviceAccountRef {namespace,name}` (required — the k8s SA allowed to exchange its token), `groups[]` (→ issued cert `O=`), `displayName`, optional `delegation` {`allowed`, `maxDepth` (3, 1–8)} lets the service use `POST /delegate`, optional `principal` (`agent`, `controller` or `service`, the default) is signed into its tokens as the `principal` claim. `metadata.name` is the issued username. |
| `ldapconfigs.ldap.authn.krateo.io` | `LDAPConfig` | An LDAP server: `dialURL` + `baseDN` (required), optional `bindDN`/`bindSecret` (anonymous bind if omitted), `tls`, `graphics`; optional `groupSearch` {`baseDN` (`spec.baseDN`), `filter` (`(\|(member={{.DN}})(uniqueMember={{.DN}}))`), `nameAttribute` (`cn`)} finds the user's groups (#72, [below](#ldap-group-search)). |
| `oauthconfigs.oauth.authn.krateo.io` | `OAuthConfig` | An OAuth2 provider: `clientID`, `clientSecretRef`, `authURL`, `tokenURL`, `redirectURL`, `scopes[]` (all required), optional `authStyle`, `restActionRef`, `graphics`. Sign-in needs `restActionRef`: its answer names the user, and must carry `subject`, the provider's stable user id (since 0.41.0). |
| `oidcconfigs.oidc.authn.krateo.io` | `OIDCConfig` | An OIDC provider: `clientID`, `redirectURI`, optional `clientSecret` (omitted: a public client, which sends no `client_secret` and must send a PKCE verifier), plus `discoveryURL` and/or explicit `authorizationURL`/`tokenURL`/`userInfoURL` (discovery fills the endpoints when any is unset), and `issuer` when there is no `discoveryURL` (#50); optional `stepUp` {`acrValues`, `maxAge` (5m), `ttl` (15m)} enables `/oidc/stepup` (#49); optional `allowedGroups[]` admits only users holding at least one of those groups (others get `403 GroupNotAllowed`); optional `additionalScopes`, `restActionRef`, `graphics`. |

`graphics` (`icon`, `displayName`, `backgroundColor`, `textColor`) styles the
frontend login button; `restActionRef` points at a snowplow RESTAction that compiles
identity fields — **functionally required for OAuth2** (the token response carries no
user info), optional enrichment for OIDC.

## The HTTP surface

All paths are **literal** (exact match, no trailing slash, wrong verb → `405`);
default port `8082`.
The table is the whole surface: `TestPublicSurface` (`go/authn/routes_test.go`) pins it, so
a new route fails CI until it is reviewed and added. The same test sends every route the
inputs a caller without valid credentials can send, and fails if any answer carries key
material, a stored credential or a secret, or if authn mints a credential.

| Method | Path | Purpose |
|---|---|---|
| GET | `/strategies` | List configured strategies for the login page: one entry per config CR (`basic` appears only if ≥1 `User` exists), with `graphics` defaults filled and `extensions.authCodeURL`/`redirectURL` for oauth/oidc. An oidc entry with a valid `spec.stepUp` adds `extensions.stepUpAuthCodeURL` (the complete step-up authorization request: `authCodeURL` with `acr_values` and `max_age` set; redirect to it as is, after setting your own `state` if you check one: authn never checks `state`), `stepUpPath` (where to POST the code), and, for display, `stepUpAcrValues` (space-separated) and `stepUpMaxAge` (seconds). The `serviceaccount` strategy is machine-to-machine and never listed. |
| GET | `/basic/login` | `Authorization: Basic` → login response. `?d` streams the kubeconfig as a file download instead. |
| POST | `/ldap/login?name=<LDAPConfig>` | JSON body `{"username","password"}` → login response. |
| GET | `/oauth/login?name=<OAuthConfig>` | `X-Auth-Code: <code>` header, plus `X-Code-Verifier: <verifier>` when the authorization request used PKCE → code exchange → RESTAction-compiled identity → login response. |
| GET | `/oidc/login?name=<OIDCConfig>` | `X-Auth-Code: <code>` header, plus `X-Code-Verifier: <verifier>` when the authorization request used PKCE, which a public client (no `clientSecret`) always must → code exchange → ID-token claims (UserInfo fallback) → login response. |
| POST | `/oidc/stepup?name=<OIDCConfig>` | Step-up (#49). Same input as `/oidc/login`, from an authorization request with `acr_values`. If the ID token's `acr` is in `spec.stepUp.acrValues` and its `auth_time` is within `maxAge`, authn mints a `krateo:loa:2` credential into `<user>-clientconfig-stepup` and returns `accessToken` (groups include `krateo:loa:2`, expiry ≤ the certificate's), `user` and `groups`, with no `data`. The session credential is untouched. |
| POST | `/serviceaccount/login` | `Authorization: Bearer <projected SA token, audience authn>` → TokenReview → allowlist mapping → login response. |
| POST | `/delegate` | Agent delegation ([design](./design/agent-delegation.md)), shaped like RFC 8693 token exchange. `Authorization: Bearer <the service's projected SA token, audience authn>`, and a form body with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt` and `subject_token=<a person's authn JWT>`. The service must be mapped with `spec.delegation.allowed`. The answer is `{access_token, issued_token_type, token_type: "Bearer", expires_in}`: a JWT with the person's `sub`, `username` and `groups`, minus reserved `krateo:loa:` groups, and RFC 8693 `act: {sub: <service>, principal: <its mapping's kind>}`, nested for a chain. The token keeps the subject token's own `principal`. It lives at most 15 minutes and never past the subject token. No kubeconfig is minted. |
| GET | `/health` | `{name,version}` once serving, `503` otherwise (process lifecycle only). |

### The login response contract

Every strategy returns the same shape:

```json
{
  "accessToken": "<RS256 JWT, kid header set — see jwt-jwks.md>",
  "user":   { "displayName": "…", "username": "…", "avatarURL": "…" },
  "groups": ["…"],
  "strategy": { "kind": "oidc", "name": "keycloak" },
  "data":   { "kind": "Config", "…": "the per-user kubeconfig" }
}
```

`strategy` says which login issued the session, in the terms of `GET /strategies`: `kind`
is `basic`, `ldap`, `oauth`, `oidc` or `serviceaccount`, and `name` is the config CR's
name (absent for `basic` and `serviceaccount`). So `kind` and `name` find the session's
`/strategies` entry, and that entry's `extensions.stepUpAuthCodeURL` says whether it
offers a step-up. A session issued by an older authn has no `strategy`. It describes the
session for a client's display logic, and authorizes nothing. `POST /oidc/stepup` returns
no `strategy`, since its token is not a session.

`data` is a complete kubeconfig whose client certificate carries
`CN=username, O=groups`: the caller's Kubernetes identity, scoped from then on by
standard RBAC. It includes the certificate's private key (`client-key-data`), so never
log a success response.

If the identity was accepted but its access token can't be signed, every login answers
`500` with `details.causes[0].reason: IssuanceFailed`. Before #48, the basic, ldap,
oauth and oidc logins answered an empty `200` in that case.

**`POST /serviceaccount/login` returns no `data`**, only `accessToken`, `user` and
`groups`. The identity's kubeconfig is still minted and stored in the
`<username>-clientconfig` Secret, where in-cluster consumers read it. Service callers
use the JWT ([#36](https://github.com/krateo-platformops/authn/issues/36)). JWT lifetime = the cert lifetime knob
(`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`, default 24h).

### What a caller should do with a failure

The tables below are the **complete** list of failure causes: `TestEveryCauseIsDocumented`
(`go/authn/causes_doc_test.go`) fails the build if the source declares a cause with no row
here. A release's notes list only what that release changed.

Each row's **Caller should** column is one of seven actions. The code says whose failure it
is; the action says what helps, which the code alone can't. A redirect flow and a password
form both answer `403`, for instance, but only one of them has something to retype.

| Caller should | Meaning |
|---|---|
| Send credentials | None were sent: ask for them (a person) or attach them (a service) |
| Retype credentials | They were refused: let the person try again |
| Start the sign-in again | This attempt can't be finished, and a fresh redirect usually succeeds. If a fresh attempt fails the same way, tell an administrator: the cause is then repeatable |
| Ask for access | The identity is proven but not allowed here. An administrator grants access; retrying won't help |
| Tell an administrator | A configuration problem. Retrying won't help until it is fixed |
| Retry later | authn or a dependency failed, possibly for a moment. Retry; if it persists, tell an administrator |
| Fix the client | The request is malformed: a bug in the caller, not something a person can fix |

### Refusals every login shares

Every login that issues a credential (basic, ldap, oauth, oidc, `/oidc/stepup`,
`/serviceaccount/login`) can also answer these, after the identity is proven and before
anything is minted ([behavior](./behavior.md#the-name-guard)):

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `UsernameUnavailable` | 403 | authn won't issue this username to this identity: it was issued to another identity, an administrator provisioned it as a basic User or ServiceAccount mapping, a RoleBinding or ClusterRoleBinding already grants rights to it, or it is reserved (`system*`, `kube-*`, `kubelet*`, `cluster-*`, `krateo:*`, `admin`, …; plumbing's `usernames` package). The last three apply to identity sources (ldap, oauth, oidc) only. The message says only that the name isn't available; the warn line `username refused` says why | Tell an administrator |
| `SystemGroupNotAllowed` | 403 | The identity carries a `system:` group (from an IdP claim, a RESTAction, LDAP, a basic User or a mapping). Kubernetes reserves that prefix for identities the apiserver vouches for | Tell an administrator |
| `PlatformGroupNotAllowed` | 403 | An identity source (ldap, oauth, oidc) asserted a `krateo:` group (from an IdP claim, a RESTAction or LDAP group search). Those carry platform rights and come only from identities an administrator provisions (basic Users, ServiceAccount mappings). authn's own `krateo:loa:` step-up group doesn't count | Tell an administrator |

A cause means the same in every table, with two exceptions. `AudienceMismatch` is the
service account's token on `/serviceaccount/login` (fix the client) and the IdP's ID
token on `/oidc/login` (tell an administrator). `TokenExpired` here is always the **ID
token the IdP just issued**, never the caller's own Krateo session.

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

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `MissingBearer` | 401 | No `Authorization: Bearer` header (also sets `WWW-Authenticate`) | Send credentials |
| `TokenNotAuthenticated` | 403 | The apiserver did not authenticate the token; its `status.error` (e.g. invalid or expired token) is in the message | Send credentials |
| `AudienceMismatch` | 403 | The token isn't bound to authn's audience (default `authn`) | Fix the client |
| `NotAServiceAccount` | 403 | The token's user isn't `system:serviceaccount:<ns>:<name>` | Fix the client |
| `NoMapping` | 403 | No `ServiceAccount` mapping allowlists this SA | Ask for access |
| `AmbiguousMapping` | 403 | More than one mapping references this SA | Tell an administrator |
| `TokenReviewFailed` | 500 | authn could not call the TokenReview API | Retry later |
| `MappingLookupFailed` | 500 | authn could not list the mappings | Retry later |
| `IssuanceFailed` | 500 | The caller was authenticated and mapped, but authn could not issue its clientconfig or sign its JWT | Retry later |

Values are added, never renamed, and a cause never changes its code. "authn was
unreachable" is the remaining case: no response at all.

### `/delegate` failures

The calling service authenticates exactly as on `/serviceaccount/login`, so every
`/serviceaccount/login` cause above applies to it, with the same code. The request's
form is checked before authn calls the apiserver. On top of those:

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `InvalidRequestBody` | 400 | The body can't be parsed as a form | Fix the client |
| `UnsupportedGrantType` | 400 | `grant_type` isn't `urn:ietf:params:oauth:grant-type:token-exchange` | Fix the client |
| `UnsupportedSubjectToken` | 400 | `subject_token_type` isn't `urn:ietf:params:oauth:token-type:jwt` | Fix the client |
| `MissingSubjectToken` | 400 | No `subject_token`, or an empty one | Fix the client |
| `DelegationNotAllowed` | 403 | The service's `ServiceAccount` mapping doesn't set `spec.delegation.allowed: true` | Ask for access |
| `SubjectTokenInvalid` | 401 | The subject token isn't a JWT authn signed with its current or a previous key, or it has expired | Send credentials |
| `DelegationTooDeep` | 403 | The actor chain, this service included, would be deeper than the mapping's `spec.delegation.maxDepth` (default 3) | Fix the client |
| `IssuanceFailed` | 500 | authn could not sign the delegated token | Retry later |

### `/oidc/login` failures

The ID token is validated before any claim is used. Every failure is a `Status` body
with the same shape as above: `400` for a request authn can't act on, `404` for an
OIDCConfig that doesn't exist, `403` for a code or token authn won't accept (retrying
the same login fails again), and `500` when authn or its IdP failed.

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `MissingConfigName` | 400 | No `?name=` | Fix the client |
| `MissingAuthorizationCode` | 400 | No `X-Auth-Code` header, or an empty one. Answered before authn looks anything up | Fix the client |
| `MissingCodeVerifier` | 400 | The OIDCConfig is a public client (no `clientSecret`) and there is no `X-Code-Verifier` header, or an empty one. Answered before authn calls the IdP: without a secret, the verifier is the only proof that the caller started the sign-in | Fix the client |
| `OIDCConfigNotFound` | 404 | No OIDCConfig has the `name` asked for | Tell an administrator |
| `AuthorizationCodeRejected` | 403 | The token endpoint refused the code itself (`error` `invalid_grant`, RFC 6749 §5.2): expired, already used, issued for another redirect URI, or a PKCE verifier that doesn't match. There is nothing to retype: start the sign-in again. If a fresh code is refused too, the cause is repeatable and needs an administrator: the authorization request's `redirect_uri` differs from `spec.redirectURI` (it can't when the client uses `/strategies`' `authCodeURL` unchanged), or the client sends the wrong verifier. The IdP answers all of these with the same `invalid_grant`, so authn can't tell them apart in the response. Its log can't either: the warn line's `reason` carries the status and the `error` code, never the IdP's `error_description`, which can name the user | Start the sign-in again |
| `IssuerMismatch` | 403 | `iss` isn't the expected issuer (exact match, including any trailing `/`) | Tell an administrator |
| `AudienceMismatch` | 403 | `aud` doesn't include `clientID`, or there are several audiences and `azp` isn't `clientID` | Tell an administrator |
| `TokenExpired` | 403 | The ID token the IdP just issued has an `exp` more than 1 minute in the past (not the caller's Krateo session). Repeating means the clocks of authn and the IdP disagree | Start the sign-in again |
| `IDTokenInvalid` | 403 | The ID token can't be decoded, `aud`/`exp` is missing or malformed, or a claim authn reads has the wrong type (`groups` not a list of strings; `preferred_username`, `name`, `picture`, `email` or `acr` not a string; `auth_time` not a number), or it has no `sub` (or an empty one), which names the identity. A `null` claim counts as omitted | Tell an administrator |
| `GroupNotAllowed` | 403 | `spec.allowedGroups` is set and the user holds none of those groups (after the RESTAction, and after reserved `krateo:loa:` groups are stripped). Applies to `/oidc/stepup` too | Ask for access |
| `IssuerUnknown` | 500 | The OIDCConfig has neither `discoveryURL` nor `issuer` | Tell an administrator |
| `IssuerConflict` | 500 | `spec.issuer` differs from the discovery document's `issuer` | Tell an administrator |
| `OIDCConfigLookupFailed` | 500 | authn could not read the OIDCConfig | Retry later |
| `OIDCDiscoveryFailed` | 500 | The `discoveryURL` document could not be read: unreachable, not `200` (a redirect is refused, not followed), or not JSON | Retry later |
| `OIDCConfigInvalid` | 500 | The authorize or token endpoint is known neither from the spec nor from discovery | Tell an administrator |
| `ClientSecretLookupFailed` | 500 | authn could not read the `clientSecret` Secret, or it has no value under the key. A named Secret never makes the client public | Retry later |
| `TokenExchangeFailed` | 500 | The code exchange failed for a reason other than the code: the token endpoint unreachable or failing, refusing authn's client credentials (`invalid_client`), redirecting (refused, never followed: the request carries the code, the verifier and, for a confidential client, the client secret), or answering something unusable. Only the status and the `error` code are logged; the IdP's answer is neither logged nor returned | Retry later |
| `UserInfoFailed` | 500 | The UserInfo call, made for claims the ID token omits, failed: unreachable, not `200` (a redirect is refused), not JSON, or a field authn asked for has the wrong type | Retry later |
| `RESTActionFailed` | 500 | The `restActionRef` RESTAction could not be resolved, or its answer isn't a usable identity. When snowplow answered, the message carries its code and its reason, when that is one of Kubernetes' StatusReasons, else `unknown` (e.g. `snowplow answered 504 Timeout`); snowplow's own message is neither returned nor logged: it can name stage URLs built from the user's identity | Retry later |
| `IssuanceFailed` | 500 | The caller was authenticated, but authn could not issue its clientconfig or sign its JWT | Retry later |

Before #81, a missing or unreadable OIDCConfig answered `417` without a cause, and
every other failure here without a cause answered `500`, including a refused code,
which is the caller's.

### `/oauth/login` failures

Same contract as `/oidc/login`. Before #81, a missing or unreadable OAuthConfig and
any failed code exchange answered `417`.

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `MissingConfigName` | 400 | No `?name=` | Fix the client |
| `MissingAuthorizationCode` | 400 | No `X-Auth-Code` header, or an empty one | Fix the client |
| `OAuthConfigNotFound` | 404 | No OAuthConfig has the `name` asked for | Tell an administrator |
| `AuthorizationCodeRejected` | 403 | The token endpoint refused the code itself: `invalid_grant`, or GitHub's `bad_verification_code` (which GitHub answers with HTTP `200`) | Start the sign-in again |
| `OAuthConfigLookupFailed` | 500 | authn could not read the OAuthConfig | Retry later |
| `ClientSecretLookupFailed` | 500 | authn could not read the `clientSecretRef` Secret, or it has no such key | Retry later |
| `TokenExchangeFailed` | 500 | The code exchange failed for a reason other than the code (see `/oidc/login`), or the token type isn't `bearer` (in any case, RFC 6749 §7.1) while a RESTAction needs it | Retry later |
| `RESTActionFailed` | 500 | The RESTAction could not be resolved, or its answer isn't a usable identity (see `/oidc/login`). Its answer must carry `name` and `subject`, the provider's stable user id (for GitHub `(.userInfo.id\|tostring)`); without `subject`, authn can't tell this user from one who takes the same login later. An OAuthConfig without `restActionRef` identifies no one and answers this too | Tell an administrator |
| `IssuanceFailed` | 500 | The caller was authenticated, but authn could not issue its clientconfig or sign its JWT | Retry later |

### `/oidc/stepup` failures

Every `/oidc/login` failure above applies, plus:

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `StepUpNotEnabled` | 403 | The OIDCConfig has no `spec.stepUp` | Fix the client |
| `InsufficientAssurance` | 403 | The ID token's `acr` isn't in `spec.stepUp.acrValues` | Start the sign-in again |
| `StaleAuthentication` | 403 | `auth_time` is missing or older than `spec.stepUp.maxAge`: redo the step-up redirect. Send `max_age` on every step-up request (`stepUpAuthCodeURL` does), since an IdP may answer `acr_values` from SSO with an old `auth_time` | Start the sign-in again |
| `StepUpMisconfigured` | 500 | `spec.stepUp` has no `acrValues`, an empty acr value or one containing whitespace, a non-positive `maxAge`, or a `ttl` under 10m (the CSR API's minimum) | Tell an administrator |
| `IssuanceFailed` | 500 | The step-up was proven, but the credential or its token couldn't be issued | Retry later |

### `/basic/login` and `/ldap/login` failures

Basic and ldap follow the same contract as `/serviceaccount/login`: every
failure is a `Status` with its cause in `details.causes[0].reason`, a refusal of the
caller is `401`/`403`, and authn's own failure is `500`. Before, both answered `403`
when authn couldn't read the User, the Secret or the LDAP server, and ldap answered
`417` when it couldn't read the LDAPConfig. An ambiguous LDAP user keeps its `300`; its
body says `"status":"Failure"` since #81 (it said `Success`).

`InvalidCredentials` is one fixed response: the same code, message and body whether
the user is unknown, the name unusable or the password wrong, so a caller can't probe
which users exist. The real reason is only in authn's log (the `reason` field of the
warn line). An unknown LDAP user was a `404` before; it is now this `403`.

`/basic/login`:

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `MissingCredentials` | 401 | No `Authorization: Basic` header (also sets `WWW-Authenticate`) | Send credentials |
| `InvalidCredentials` | 403 | Unknown user, unusable user name or wrong password, answered alike | Retype credentials |
| `UserLookupFailed` | 500 | authn could not read the `User` | Retry later |
| `PasswordSecretMissing` | 500 | The `User` has no `passwordRef`, or its Secret or key doesn't exist | Tell an administrator |
| `PasswordLookupFailed` | 500 | authn could not read the password Secret | Retry later |
| `IssuanceFailed` | 500 | The caller was authenticated, but authn could not issue its clientconfig or sign its JWT | Retry later |

`/ldap/login`:

| `details.causes[0].reason` | Code | Meaning | Caller should |
|---|---|---|---|
| `MissingConfigName` | 400 | No `?name=` | Fix the client |
| `InvalidRequestBody` | 400 | The body isn't the JSON `{"username","password"}`. An empty body is not refused here: the login goes on with an empty username and password | Fix the client |
| `LDAPConfigNotFound` | 404 | No LDAPConfig has the `name` asked for | Tell an administrator |
| `AmbiguousUser` | 300 | More than one entry matches the username | Tell an administrator |
| `InvalidCredentials` | 403 | No entry matches the username, the server refused the user's bind (wrong password, account disabled), or the password is empty, answered alike | Retype credentials |
| `LDAPConfigLookupFailed` | 500 | authn could not read the LDAPConfig or its bind Secret | Retry later |
| `LDAPConfigInvalid` | 500 | `spec.groupSearch.filter` doesn't parse as a template, can't render, or doesn't render an LDAP filter. Found before authn connects to the server | Tell an administrator |
| `LDAPUnavailable` | 500 | authn could not connect to the LDAP server: dial, StartTLS, or a dropped connection | Retry later |
| `LDAPBindFailed` | 500 | The server refused the `bindDN` bind (wrong or missing `bindSecret`), or failed the user's bind for a reason other than their credentials | Tell an administrator |
| `LDAPSearchFailed` | 500 | The user or group search failed, e.g. `baseDN` doesn't exist | Tell an administrator |
| `IssuanceFailed` | 500 | The caller was authenticated, but authn could not issue its clientconfig or sign its JWT | Retry later |

Every `Status` whose code isn't `2xx` says `"status":"Failure"`. Before #81 a `400` or a
`300` said `Success`.

### LDAP group search

After the user's bind succeeds, authn searches for the user's groups, and each entry
found is one group (the certificate's `O=` and the JWT's `groups`). The groups are
exactly what this search finds, each name once, without reserved `krateo:loa:` names;
the user entry's own attributes, such as `ou`, are not groups. `spec.groupSearch`
configures the search (#72); every field is optional, and an empty one takes its default:

| Field | Default | Meaning |
|---|---|---|
| `baseDN` | `spec.baseDN` | The subtree searched |
| `filter` | `(\|(member={{.DN}})(uniqueMember={{.DN}}))` | A Go `text/template` rendering the search filter for the user |
| `nameAttribute` | `cn` | The group entry attribute that names the group. An entry without it is skipped. Matched case-insensitively |

The template has two fields, each escaped for an LDAP filter before it is substituted,
so neither can inject filter syntax (`*`, `(`, `)`, `\`, NUL and non-ASCII bytes
become `\2a`-style escapes):

| Field | Value |
|---|---|
| `{{.DN}}` | The DN the user bound as, from the user search |
| `{{.Username}}` | The login name sent in the request body |

The default covers `groupOfNames` and Active Directory (`member`) and
`groupOfUniqueNames` (`uniqueMember`). For `posixGroup`, which lists members by
login name:

```yaml
spec:
  groupSearch:
    baseDN: ou=groups,dc=example,dc=org
    filter: (&(objectClass=posixGroup)(memberUid={{.Username}}))
```

The filter is not recursive: Active Directory's nested groups need the matching rule
in the filter, e.g. `(member:1.2.840.113556.1.4.1941:={{.DN}})`.

Before #72 a user entry's `ou` values were its groups, and the group search counted only
for a user without any. A deployment whose RBAC binds those `ou` values must bind real
directory groups instead, or set a `groupSearch.filter` that returns them.

Full request/response semantics, per-strategy validation rules and error mapping:
[behavior.md](./behavior.md).
