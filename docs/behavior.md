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
| POST   | `/delegate`     | Agent delegation: a mapped service's SA token plus a person's authn JWT → a short-lived JWT naming the person (`sub`) and the service (`act`) | `internal/routes/delegate/delegate.go` |
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
  "strategy": { "kind": "oidc", "name": "..." },
  "data":   <base64-free JSON kubeconfig (Kind: Config)>
}
```

- `strategy` names the login that issued the session, in `/strategies`' terms. Each login
  route sets it on `encode.Extras`; `name` is absent for `basic` and `serviceaccount`,
  and a step-up sets none.
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
  It carries `principal`, the kind of identity, which each login sets in
  `encode.Extras.Principal`: `human` for basic, LDAP, OAuth, OIDC and step-up, and the
  mapping's kind for a service. `successBody` refuses to sign without a known one
  (`500 IssuanceFailed`), so a login can't issue a token that omits it.
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
  is **not** checked: the token comes back-channel, directly from the configured token
  endpoint over TLS, which OIDC Core §3.1.3.7 accepts in place of it. A confidential
  client authenticates that exchange with its secret; a public one binds it to the
  sign-in with the PKCE verifier, which it must send. A non-`200` from the token endpoint is classified like oauth's
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
- `spec.delegation` (optional) — `allowed: true` lets the service exchange a person's
  authn JWT at `POST /delegate`, and `maxDepth` (default 3, 1–8) caps the actor chain,
  its own link included. Omitted or `allowed: false`: `403 DelegationNotAllowed`.
  The subject token is verified against authn's current and previous keys
  (`delegate.keySet`). The issued token keeps the subject's `username` and `groups`,
  minus reserved ones, and its `principal`, adds `act` (`plumbing/jwtutil.Actor`) with
  this service's `principal`, and lives `min(15m, subject exp)`. It mints no kubeconfig.
- `spec.principal` (optional, `agent` | `controller` | `service`) — the kind of identity
  this service is, signed into its tokens as the `principal` claim
  (`serviceaccount.Principal`). Omitted: `service`.

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
- `spec.clientID`, `spec.redirectURI`.
- `spec.clientSecret` (optional `SecretKeySelector`). Set, the client is confidential:
  the Secret must hold a non-empty value under the key, or every login fails `500`
  `ClientSecretLookupFailed`, and the token exchange sends it as `client_secret`.
  Omitted, the client is public (`oidcConfig.Public`, `oidc/support.go`): no
  `client_secret` is sent, and a login without `X-Code-Verifier` is refused `400`
  `MissingCodeVerifier` before the IdP is called (`doLogin`), for `/oidc/stepup` too.
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
equivalent). authn then watches the CSR, so the login continues as soon as the signer
issues the certificate; a denied or failed CSR ends it at once, and no certificate within
5 minutes fails it. The minted cert's CN = username and O = groups become the caller's
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
(`internal/helpers/outbound`): the IdP's token endpoint (the code, the PKCE verifier and a
confidential client's secret in the body), UserInfo (the user's token), discovery, and snowplow
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
- **No fallback.** Through 0.37, `LegacyResolve` served RESTActions without a
  `${ .token }` header: it copied the RESTAction and its endpoint Secrets per user, with
  the user's token written in. krateo-saas#44 gave its `github-oauth-restaction` the
  header, and demo's hand-applied copy got it on 2026-11-08; GitHub sign-ins there then
  logged no fallback, so the path was deleted. A RESTAction must now read the token as
  `${ .token }`, or sign-in fails with `500` `RESTActionFailed`. The namespaced Role lost its
  `restactions` write rule with it. snowplow's cluster-wide `get` on `restactions` for
  group `authn` stays: snowplow resolves the RESTAction as authn.

The returned `status` map may set `subject`, `name`, `email`, `preferredUsername`,
`groups`, `avatarURL` (`updateConfig`); a wrong type for one of them is
`RESTActionFailed`, and any other key is ignored. On OAuth, `name` and `subject` are
required: `subject` is the provider's stable user id, the identity the name guard
checks (below). On OIDC, `subject` is ignored: the identity is the ID token's `iss` and
`sub`, which no RESTAction can change.

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
| `authn.krateo.io/claim` | the identity the username was issued to, as a JSON array `[strategy, issuer, id]` (see [the name guard](#the-name-guard)); since 0.41.0 |

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

### A service identity's Secret is owned by its mapping
`/serviceaccount/login` stores the identity's `<username>-clientconfig` Secret with one
ownerReference: its `ServiceAccount` mapping (`serviceaccount.authn.krateo.io/v1alpha1`,
by name and **UID**; not a controller reference, not blocking). When the mapping is
deleted, for example by core-provider retiring a composition controller, the Kubernetes
garbage collector deletes the Secret. Nobody else needs delete rights on Secrets, and
authn runs no pruning loop (`config.OwnedBy`, `storage.AuthInfo.Owner`).

- **Re-created mapping:** a mapping deleted and created again has a new UID, so the
  collector removes the old Secret, and the next login writes a new one owned by the new
  mapping. A mapping updated in place keeps its UID and its Secret.
- **Backfill:** at startup, in the operator namespace, a `serviceaccount` Secret with **no
  owner** gets its mapping as owner. A Secret that already has an owner is left alone, so
  a credential issued under an earlier mapping of the same name is never re-attached to a
  newer one. A `serviceaccount` Secret whose mapping is gone is logged as `service
  clientconfig has no ServiceAccount mapping; left in place` (with its `notAfter`) and
  counted as `orphaned`. Deleting it is an operator's decision.
- People's Secrets (basic, LDAP, OAuth, OIDC, step-up) and authn's own have no owner.

### The name guard
A certificate's CN is a Kubernetes username, and the cluster grants that name whatever
its RoleBindings and ClusterRoleBindings grant it. An identity source (LDAP, an OAuth
RESTAction, an OIDC IdP) chooses the name. So before anything is minted, on every login
and step-up, authn checks that the name may go to this identity
(`config/guard.go`). Since 0.41.0.

**The subject.** Every login names the identity it proved, stably across logins and
renames (`userinfo.Subject`):

| Strategy | Issuer | ID |
|---|---|---|
| basic | the User's namespace | the User's name |
| ldap | the LDAPConfig's name | the entry's DN |
| oauth | the OAuthConfig's name | the RESTAction's `subject` (required) |
| oidc | the ID token's `iss` | its `sub` (required) |
| serviceaccount | the ServiceAccount's namespace | its name (a re-created mapping keeps it) |

The claim recorded on the Secret is `[strategy, issuer, id]`. The same person through two
strategies is two identities.

**The rules**, in order. A refusal is `403` `UsernameUnavailable`, logged as the warn line
`username refused` with the reason; the response says only that the name isn't
available. A failed read is `500` `IssuanceFailed`.
1. An identity source may not take a **reserved** name: `admin`, `administrator`,
   `root`, `masterclient`, `nodeclient`, `aksservice`, or one starting with `system`,
   `kube-`, `kubelet`, `cluster-`, `gke-`, `eks-` or `aks-`. The names the platforms give
   their own components, which the cluster may grant rights to before any binding names
   them.
2. If the name's session Secret has a **claim**, the name goes only to that identity.
3. A Secret written **before claims existed** is adopted by the first login of the
   strategy that wrote it (`authn.krateo.io/strategy`). A basic User or a mapping also
   adopts one whose strategy is `unknown` or missing, since an administrator chose its
   name. An identity source never adopts one of unknown origin.
4. With no Secret, a basic User or a mapping gets its name: an administrator chose it.
   An identity source doesn't if an administrator **provisioned** the name as a basic
   User or a ServiceAccount mapping, or if any RoleBinding or ClusterRoleBinding in the
   cluster names it as a **User subject**. That covers users the platform binds for its
   own components, and names bindings were written for before anyone signed in.
   Bindings written for a person after their first login belong to their claim.

**Groups.** No login may issue a `system:` group, from any source: `403`
`SystemGroupNotAllowed`. Kubernetes' CertificateSubjectRestriction admission only blocks
`system:masters`; other `system:` groups (`system:nodes`, `system:bootstrappers`) would
otherwise pass.

**Operating it.**
- The RBAC check lists every RoleBinding and ClusterRoleBinding, so the chart grants
  authn `list` on both. It runs only on an identity source's first claim of a name; a
  claimed name is decided from its Secret.
- Deleting a person's clientconfig Secret releases the claim. If a binding still names
  them, their next login is then refused until an administrator removes or rewrites that
  binding.
- Two first logins of different identities with the same new name, at the same moment,
  can both pass the check. The write settles it: storing over a Secret claimed by
  another identity is refused (`UsernameUnavailable`), and the certificate just minted
  is neither stored nor returned (`storage.ErrClaimedByAnother`).

### Audit records
With `OTEL_LOGS_ENABLED` on (default `OTEL_ENABLED`, which the chart turns on), authn writes one audit record (audit
library schema v1, AUDIT-4) per credential it writes for a verified caller, and one per
`/delegate` decision about an authenticated actor. Records go to the OTLP logs pipeline
and nowhere else: their attributes carry identity on purpose, so they never reach a span
or a log line.

| Emit site | `krateo.action` | Target | Verb |
|---|---|---|---|
| basic, LDAP, OAuth, OIDC, ServiceAccount login | `authn.login.<strategy>` | the `<username>-clientconfig` Secret | `create` or `update`, as sent |
| OIDC step-up | `authn.stepup.oidc` | the `<username>-clientconfig-stepup` Secret | `create` or `update` |
| `/delegate` | `authn.delegate` | the actor's `serviceaccount.authn.krateo.io` mapping | `get` |
| step-up sweep (background) | `authn.stepup.expired` | the expired step-up Secret | `delete` |
| authn's own certificate (background) | `authn.servicecert.issued` | authn's `<authn-username>-clientconfig` Secret | `create` or `update`, as sent |

- **Login, step-up.** A record is written right after the credential is issued, whatever
  the outcome:
  - `success`, with the apiserver's status for the request that stored the Secret (201 or
    200) and the stored uid;
  - `denied` when authn refused the verified identity: the name guard, a `system:` group,
    or an OIDCConfig's `allowedGroups`. The target is the Secret it would have written,
    with the verb it would have sent, and no status code, since authn refused before
    asking the apiserver;
  - `failure` when the issuance failed after verification.

  A caller refused before verification (wrong password, invalid token) gets no record. On
  an OAuth or OIDC callback the record keeps the path only, because the query carries the
  authorization code and state.
- **`/delegate`.** The actor is the mapping's name, of the class its `spec.principal`
  declares. A record carries `on_behalf_of` and the delegation chain once the subject token
  is read. It's `denied` for `DelegationNotAllowed` and `DelegationTooDeep`, and `failure`
  when signing fails.
- **Background.** The sweep's deletes and the writes of authn's own certificate (its first
  issue and every renewal) are `controller` rows from a second scope
  (`github.com/krateo-platformops/authn/audit/controller`), with authn's own
  ServiceAccount (`POD_SERVICE_ACCOUNT`) as actor and the status the apiserver answered.
  The certificate's write is reported by plumbing's `signup.DoWritten`
  (`endpoints.StoreWritten`). A renewal that fails before the Secret write (at the CSR)
  sends nothing for the Secret, so there is nothing to record. Its failure shows in authn's
  log (`issuing a client certificate`), and the renewer retries a minute later.
- **The CSR is a step, not a record.** Every login and renewal creates, approves and
  deletes a `certificates.k8s.io` CertificateSigningRequest. Those are steps of one
  issuance (#119's scope), and the record names the credential Secret they produce. A
  login whose CSR step fails still has its record, a `failure` naming the Secret it would
  have written, so a failed issuance is never silent. The annotation updates that follow (the validity
  window) change no data and are not recorded.
- **Every record** carries the request's `session.id` (inbound W3C baggage, or minted per
  request), the source IPs, the user agent and whether the target's namespace is a
  preview sandbox (from the Namespace's labels, read and cached for 5 minutes; the chart
  grants `get` on authn's own Namespace only). Its body is a closed set of texts, never an
  error's. A request that wrote a record marks its Server span
  `krateo.audit.recorded=true`. A failed export never blocks a login: the SDK retries and
  then drops, and `authn.audit.export.failed` counts the dropped records.

### Frontend
The frontend consumes `/strategies` to render the login page and the login response
(`data` + `accessToken`) to authenticate the user. CORS is enabled by default with
`*` origin; the allowed headers include the custom `X-Auth-Code` and `X-Code-Verifier` plus the W3C
trace-context headers `traceparent`/`tracestate`/`baggage` (`main.go:257-270`).
