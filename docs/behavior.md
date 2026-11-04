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
  so the frontend can start the provider redirect (`strategies.go`, `forOIDC` and
  `forOAuth`).
- The `state` in an oidc `authCodeURL` is random per `/strategies` call. authn never
  stores or checks it: neither `/oidc/login` nor `/oidc/stepup` receives `state`. A
  client that wants CSRF protection sets its own `state` (e.g.
  `URL.searchParams.set('state', …)`, never by cutting the URL) and verifies it on the
  redirect back.
- An `oidc` entry whose OIDCConfig has a valid `spec.stepUp` also carries the step-up
  hints (`oidc.StepUpExtensions`): `stepUpAuthCodeURL` (the entry's `authCodeURL`
  parsed, with `acr_values` and `max_age` set and every other parameter kept),
  `stepUpPath` (`/oidc/stepup`), `stepUpAcrValues` (the `acrValues`, space-separated)
  and `stepUpMaxAge` (`maxAge` in seconds). The portal redirects to
  `stepUpAuthCodeURL` as is, then POSTs the code to `stepUpPath`; it never composes
  the URL itself. `max_age` makes the IdP re-authenticate a user whose last
  authentication is too old, instead of authn refusing the step-up as
  `StaleAuthentication`. A misconfigured `spec.stepUp`, or an `authCodeURL` that isn't
  an absolute URL, is not advertised and is logged as a warning.

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
  Its `client-key-data` is a private key ([gotchas](./gotchas.md)).
- **`/serviceaccount/login` omits `data`.** It still mints the identity and persists the
  `<username>-clientconfig` Secret (which snowplow, plumbing endpoints and bff read), but
  the response carries only `accessToken`, `user` and `groups`. No service caller reads
  the kubeconfig, and leaving it out means a printed or logged success response can't
  leak the key ([#36](https://github.com/krateo-platformops/authn/issues/36),
  `serviceaccount/login.go`).
- `accessToken` is always present, since authn fails to boot without a valid signing key. The JWT
  duration is the cert-duration knob (8h default if none is given), **clamped to the issued
  certificate's real `NotAfter`**, so a token never outlives the credential minted with it
  (`tokenDuration`, `success.go:37`; [certificate-renewal](./certificate-renewal.md)).
- `/basic/login?d` instead returns the kubeconfig as a file download
  (`Content-Disposition`, `basic/login.go:94-96` → `encode/attach.go`).

### Log level of a failed login

A failed login is logged at the level its status code implies: a refusal of the caller
(`401`/`403`, and any other `4xx`) at **warn**, authn's own failure (`5xx`) at
**error**. Routes that answer with `status.FromError(err)` log with
`status.LogFailure(log, err)` (`internal/status/log.go`), which picks the level from
the same code and adds `code` and `cause` (`details.causes[0].reason`) to the line.
So an alert on error-level logs fires for authn's failures, not for callers with a bad
or expired credential. Every login answers this way since #81, which replaced the oauth
and oidc `417`s: a refused authorization code is a `403` (`AuthorizationCodeRejected`,
warn), any other failed exchange a `500` (`TokenExchangeFailed`, error).

### Login inputs per strategy

- **basic** — HTTP `Authorization: Basic` header; `401` `MissingCredentials` with
  `WWW-Authenticate` if absent. Password compared in constant time (SHA-256 digests, `subtle.ConstantTimeCompare`) against the plaintext in the Secret
  keyed by `User.spec.passwordRef` (`validate`, `basic/login.go`). An unknown user and
  a wrong password are the same refusal, `403` `InvalidCredentials`, with a
  byte-identical body; the real reason is logged only (`status.RefusedPrivately`). A
  User or Secret authn can't read, or a Secret that is missing or lacks the key, is a
  `500` with its
  cause (`UserLookupFailed`, `PasswordLookupFailed`, `PasswordSecretMissing`). Every
  failure is a `Status` with `details.causes[0].reason` ([api](./api.md)).
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
  `metadata.name`, groups = `spec.groups`, and `displayName` from the mapping. A
  refused caller (token not authenticated, wrong audience, not an SA, no or ambiguous
  mapping) gets `403`. A failure on authn's side (TokenReview call, mapping list,
  clientconfig or JWT issuance) gets `500`. Every failure, including the
  missing-bearer `401`, is a JSON `Status` whose `details.causes[0].reason` names the
  cause (`status.FromError`, `internal/status`; [api](./api.md)).
- **ldap** — `?name=<LDAPConfig>` + JSON body `{"username","password"}`
  (`ldap/login.go`). Past the `400`s for a missing `name` or a bad body, every failure
  is a `Status` with `details.causes[0].reason` ([api](./api.md)), classified in `getConfig` and `doLogin` (`ldap/support.go`):
  an unknown LDAPConfig → `404` `LDAPConfigNotFound` (was `417`); several matching
  entries → `300` `AmbiguousUser`; no matching entry, or the user's own bind refused
  (LDAP result 49, 48 or 53, or an empty password) → `403` `InvalidCredentials`, one
  byte-identical body with the real reason logged only.
  authn's side is a `500`: the LDAPConfig or its bind Secret unreadable
  (`LDAPConfigLookupFailed`), dial, StartTLS or a dropped connection
  (`LDAPUnavailable`), the `bindDN` bind refused or a user bind failing for another
  reason (`LDAPBindFailed`), the user or group search failing, e.g. `NoSuchObject` for
  a wrong `baseDN` (`LDAPSearchFailed`), and a `spec.groupSearch.filter` that isn't a
  usable template (`LDAPConfigInvalid`).
  After the user's bind, the groups come from a second search configured by
  `spec.groupSearch` (#72; [api](./api.md#ldap-group-search)): under
  `groupSearch.baseDN` (default `spec.baseDN`), with `groupSearch.filter` rendered as a
  Go `text/template` whose `.DN` (the DN the user bound as) and `.Username` (the login
  name) are `ldap.EscapeFilter`-escaped (default
  `(|(member={{.DN}})(uniqueMember={{.DN}}))`), keeping each entry's
  `groupSearch.nameAttribute` (default `cn`, matched case-insensitively; an entry
  without it is skipped). `getConfig` parses the template and checks a sample
  rendering with `ldap.CompileFilter`, so a bad one fails before authn dials the server.
  The user's groups are exactly the names found, in order, each once (`groupNames`),
  through `userinfo.NewDefaultUser`, which drops reserved `krateo:loa:` names; the user
  entry's `ou` is no longer read. The user search asks only for `uid`, `cn` and `mail`,
  the attributes `ldapEntryToUserInfo` reads; it used to ask for `userPassword`,
  `memberof`, `ou` and `o` too, so a bind DN allowed to read password hashes received
  them on every login. Before #72 the filter was hardcoded to
  `(uniquemember=uid=<username>,dc=example,dc=com)`, so outside that one directory
  layout every login got no groups, and a user entry's `ou` values, when it had any,
  were its groups instead.
- **oidc step-up** — `POST /oidc/stepup?name=<OIDCConfig>`, with the same headers as
  the OIDC login (#49). It runs the same flow as `/oidc/login` (`authenticate`,
  `oidc/login.go`), then `checkStepUp` (`oidc/stepup.go`):
  - `spec.stepUp` is set;
  - the ID token's `acr` is listed;
  - `auth_time` is within `maxAge`.

  `acr` and `auth_time` come only from the validated ID token; the RESTAction can't set
  them. The identity gains `krateo:loa:2` (`userinfo.NewStepUpUser`, the only way to
  get a reserved group), and `GenerateStepUp` stores it as
  `<user>-clientconfig-stepup` with `ttl`. The JWT carries the same groups and ends
  with the certificate. The user's `<user>-clientconfig` is never written, so their
  normal session is unchanged. Expired step-up Secrets are deleted by the leader-only
  sweep (`internal/stepupsweep`): every 5 minutes, 5 minutes after the certificate's
  `notAfter`, read from the certificate itself, with UID and resourceVersion
  preconditions so a step-up that rewrote the Secret keeps it.
- **oauth** — `?name=<OAuthConfig>` + `X-Auth-Code` header (`oauth/login.go`), and
  optionally `X-Code-Verifier`, forwarded as the PKCE `code_verifier`
  (`oauth2.VerifierOption`) exactly as on oidc; before, `/oauth/login` dropped it, so a
  client that sent a `code_challenge` got every exchange refused.
  Code is exchanged via `golang.org/x/oauth2`; token type must be `bearer`, compared
  case-insensitively (RFC 6749 §7.1), when a RESTAction is configured. A failed exchange is classified by `classifyExchange` →
  `codeexchange.Refusal` (`internal/helpers/codeexchange`): the token endpoint's
  `error` `invalid_grant`, or GitHub's `bad_verification_code` (answered with HTTP
  `200`, which `x/oauth2` still reports as a `RetrieveError`), is `403`
  `AuthorizationCodeRejected`; anything else is `500` `TokenExchangeFailed`. The
  provider's answer goes to the log only (`CauseError.Private`). Every failure is a
  `Status` with a cause ([api](./api.md#oauthlogin-failures)).
- **oidc** — `?name=<OIDCConfig>` + `X-Auth-Code` header (a missing one is `400`
  `MissingAuthorizationCode` before any lookup), and optionally
  `X-Code-Verifier`. Code is POSTed to the token endpoint, with the PKCE
  `code_verifier` (RFC 7636) when the header is present. authn doesn't generate PKCE
  itself: the client that builds the authorization request adds the
  `code_challenge`, keeps the verifier, and sends it back in `X-Code-Verifier`; ID-token claims (`preferred_username`, `name`, `picture`, `email`,
  `groups`) are read, and the UserInfo endpoint is called only for the claims the ID
  token omits. `groups` is never sourced from UserInfo. Every claim is read with
  `stringClaim`/`stringListClaim` (`oidc/support.go`): absent or `null` is omitted (and
  asked of UserInfo), any other wrong type is `403` `IDTokenInvalid` from the ID token
  and `500` `UserInfoFailed` from UserInfo. Unchecked type assertions used to panic the
  request, and net/http then dropped the connection without answering.
  Before any claim is read, the ID token is validated (`validateIDToken`,
  `oidc/idtoken.go`, #50): `iss` must equal the expected issuer, `aud` must contain
  `clientID` (and `azp` must equal it when there are several audiences), and `exp`
  must not be more than 1 minute past. The expected issuer is the discovery document's
  `issuer` when `discoveryURL` is set (a different `spec.issuer` is a conflict),
  otherwise `spec.issuer`. With neither, every login is refused with `500`
  `IssuerUnknown`, and authn logs a warning naming the config at startup. The signature
  is **not** checked: the token comes back-channel from the configured token endpoint,
  authenticated with the client secret over TLS, which OIDC Core §3.1.3.7 accepts in
  place of it. A non-`200` from the token endpoint is classified like oauth's
  (`codeexchange.Refusal` on its JSON `error`), and `getConfig` (`oidc/support.go`)
  gives every config failure its cause: `404` `OIDCConfigNotFound`, `500`
  `OIDCConfigLookupFailed`, `OIDCDiscoveryFailed` (`resolvers.ErrDiscoveryFailed`),
  `OIDCConfigInvalid` (`resolvers.ErrEndpointsMissing`), `ClientSecretLookupFailed`.

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
- `spec.groupSearch` (optional, #72) — the search for the user's groups: `baseDN`
  (default `spec.baseDN`), `filter` (a `text/template` over the escaped `.DN` and
  `.Username`; default `(|(member={{.DN}})(uniqueMember={{.DN}}))`), `nameAttribute`
  (default `cn`). An invalid `filter` fails every login with `500`
  `LDAPConfigInvalid`.
- `spec.graphics` (optional).

### `OIDCConfig` (`oidc.authn.krateo.io`) — `apis/authn/oidc/v1alpha1/types.go`
- `spec.clientID`, `spec.clientSecret` (`SecretKeySelector`), `spec.redirectURI`.
- `spec.discoveryURL`, `spec.authorizationURL`, `spec.tokenURL`, `spec.userInfoURL`,
  `spec.additionalScopes`. With `discoveryURL` the document is read on every login
  (it supplies the issuer); its endpoints are applied only when some endpoint is unset.
- `spec.allowedGroups` (optional) — when non-empty, a user is admitted only if their
  final groups (ID token or RESTAction, reserved `krateo:loa:` groups already stripped)
  include at least one entry. Anyone else gets `403 GroupNotAllowed` at `/oidc/login` and
  `/oidc/stepup`, and nothing is minted. Empty: everyone the IdP authenticates is
  admitted and RBAC alone decides. It's defence in depth on top of the IdP's own gate,
  e.g. a per-child Keycloak client admitting `child:<name>:member`.
- `spec.stepUp` (optional) — enables `POST /oidc/stepup` (#49): `acrValues` (≥1, the
  `acr` values that prove LoA2; each non-empty and without whitespace), `maxAge` (default 5m, how recent `auth_time` must be),
  `ttl` (default 15m, ≥10m, the step-up credential's requested lifetime, never
  renewed).
- `spec.issuer` (optional) — the ID token's expected `iss`. Required without
  `discoveryURL`; with it, must equal the discovered issuer or be left empty.
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
On every successful login (and step-up) the generator creates a `CertificateSigningRequest`, named `<username>-<random>` and deleted once its certificate is read, with
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

### Outbound calls refuse redirects
Every call authn makes to another service goes through `outbound.Client()`
(`internal/helpers/outbound`): the IdP's token endpoint (the client secret, code and
PKCE verifier in the body), UserInfo (the user's token), discovery, and snowplow
(authn's JWT, plus the user's token in the body). It refuses every redirect
(`ErrRedirectRefused`). net/http alone isn't enough: it keeps `Authorization` on a hop to
a subdomain or another port, and a 307/308 resends the body to wherever `Location`
points. A refusal fails the call with its existing cause (`TokenExchangeFailed`,
`UserInfoFailed`, `OIDCDiscoveryFailed`, `RESTActionFailed`), and the redirect's target
host is logged. The client is built fresh on each call, so `http.DefaultClient` is never
changed.

### snowplow (identity enrichment)
When an `OIDCConfig`/`OAuthConfig` has a `restActionRef`, authn enriches the identity
by asking snowplow to resolve that RESTAction (`internal/helpers/restaction/resolver.go`),
authenticating with the long-lived `authn` service JWT. Two resolution paths:
- **`Resolve`** — `POST /call/read?apiVersion=templates.krateo.io/v1&resource=restactions&name=…&namespace=…`
  (query escaped) with body `{"extras":{"token":"<the user's IdP access token>"}}`.
  **Requires snowplow ≥ 1.12.28**, the first with `/call/read`. Before 0.35.2 the token
  went in the URL (`GET /call?…&extras={"token":…}`, unescaped), where any URL-logging
  gateway, and authn's own trace spans when tracing is on, recorded it. A RESTAction
  reads the token as `${ .token }`. Put it in a stage **header**
  (`"${ \"Authorization: Bearer \" + .token }"`), never in a stage **path**: snowplow
  logs a failing stage's path unredacted (snowplow #1143). A non-`200` from snowplow is
  a `SnowplowError` (its code, `reason` and `message`). The caller gets `500`
  `RESTActionFailed` with the code and reason; the message stays in authn's log
  (`restaction.Failed`).
- **`LegacyResolve`** — the fallback for RESTActions written for the old shape, whose
  stages carry no `${ .token }` header. It runs when `Resolve` fails, or its answer is
  unusable (oidc: `checkKeys`; oauth: no `name`). It copies the RESTAction and its
  endpoint Secrets per user, with the user's token written into each Secret copy under
  `token` (unless the Secret already has one), calls `GET /call` on the copy, then
  deletes the copies. **Every use logs a warn**, `restaction fell back to the legacy copy
  path`, naming the RESTAction. It is deleted once no live RESTAction needs it: the
  krateo-saas `github-oauth-restaction` is the known one (no `.token` header).

The returned `status` map may override `name`, `email`, `preferredUsername`, `groups`,
`avatarURL` (`updateConfig`, `oidc/support.go`). On oidc, any other key makes the
answer unusable (`checkKeys`).

The snowplow base URL comes from `SNOWPLOW_SERVICE_HOST`/`SNOWPLOW_SERVICE_PORT` or
`URL_SNOWPLOW` (default `http://snowplow.krateo-system.svc.cluster.local:8081`,
`main.go:63-72`).

### Stored AuthInfo
Each `Generate` persists an `AuthInfo` (cert/key/CA/server) via the storage layer:
a Secret per identity (`config/build.go`, `config/storage/storage.go`). authn only
writes it; in-cluster consumers such as snowplow read it under RBAC. No HTTP route
returns it (`GET /info` was removed in 0.31.0).

### Identity annotations on `<username>-clientconfig`
Every clientconfig Secret authn writes carries, besides the certificate's granted window
(`authn.krateo.io/certificate-not-{before,after}`), the identity facts policy can decide
from ([#42](https://github.com/krateo-platformops/authn/issues/42),
`config/storage/identity.go`):

| Annotation | Value |
|---|---|
| `authn.krateo.io/strategy` | `basic`, `ldap`, `oauth`, `oidc`, `serviceaccount`; `self` for authn's own identity (`authn-clientconfig`); `unknown` only from the backfill below |
| `authn.krateo.io/groups` | the certificate's `O=` groups, **newline-separated**, in order; empty for none |

- **Why newlines:** group names can contain commas (OIDC passes IdP names verbatim).
- **CEL membership test:** `annotations['authn.krateo.io/groups'].split('\n').exists(g, g == 'admins')`.
- **Newline in a group name:** the login is refused before any certificate is minted
  (`ValidateGroups`), because that group could not be recorded faithfully.

**Backfill.** At startup, `internal/identitybackfill` stamps clientconfigs that predate these
annotations, and never overwrites existing ones:
- groups come from the stored certificate;
- strategy is `self`, `serviceaccount` (a mapping with that username exists) or `basic`
  (a basic `User` exists);
- otherwise strategy is `unknown`, including when both a mapping and a basic `User`
  exist. Policy should fail closed on `unknown`.

A Secret whose certificate can't be read, or whose lookup fails, is skipped and logged,
never stamped with a guess. The next start retries it.

### Frontend
The frontend consumes `/strategies` to render the login page and the login response
(`data` + `accessToken`) to authenticate the user. CORS is enabled by default with
`*` origin; the allowed headers include the custom `X-Auth-Code` and `X-Code-Verifier` plus the W3C
trace-context headers `traceparent`/`tracestate`/`baggage` (`main.go:257-270`).
