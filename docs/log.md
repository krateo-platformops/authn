---
type: Log
title: authn — log
description: Curated chronological history — notable changes, decisions and incidents; release notes stay in GitHub Releases.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [history]
timestamp: 2026-08-07T00:00:00Z
---

# Log

Curated history, newest first. Durable decisions live in
[`docs/design/`](./design/); the code-traced internals corpus is
[architecture](./architecture.md) / [behavior](./behavior.md) /
[gotchas](./gotchas.md).

## 2026-11-06 — debug is off by default, and the environment dump is gone

The chart shipped `AUTHN_DEBUG=true` and `AUTHN_DUMP_ENV=true`, so production wrote its
whole environment as one line at each start, and that line falsely tripped
`sre-certificate-expiry-warning` on every authn restart. Debug also logged each OIDC and
OAuth sign-in's name, username, email, groups and avatar URL, and the values a RESTAction
adds. Info-level login lines keep the username and groups, on purpose. Observability
found the dump, and its count found ten matching lines on demo. Diego chose to set debug
off in the chart and delete `--dump-env` and `AUTHN_DUMP_ENV`: `kubectl` already shows this
configuration, and a future secret in the environment can't reach the logs this way.
`AUTHN_DEBUG` remains as an override for debugging, with the personal data that brings.

## 2026-11-06 — an unknown basic user costs a Secret read too

A known user cost a Secret read that an unknown user didn't, so response time could reveal
which usernames exist even though the `403` bodies are identical. Diego chose a decoy Secret
over a minimum response time, which would have slowed every mistyped password and left a
number to tune. The chart now installs `<fullname>-basic-decoy`, and `/basic/login` reads it
for an unknown user. It holds no credential: the login is refused whatever it contains. A
failed read stays a `403 InvalidCredentials`, because a `500` would say the name is unknown,
and the reason goes to the log.

## 2026-11-06 — a login no longer waits a fixed 3s for its certificate

`WaitForCertificate` polled the CSR every 3s and made its first check only after the first
interval, so every login that issues a clientconfig, on any strategy, waited at least 3s
after approving the CSR. snowplow's run 21 measured a basic login at a 3.2s median, which
that wait fits, though the steps weren't timed separately. Diego chose a watch over a
faster poll: `WaitForCertificate` now uses client-go's `csr.WaitForCertificate`, which lists
then watches, so a certificate issued before the watch starts isn't missed. It returns the
certificate, so the separate read is gone, and a denied or failed CSR ends the wait at once
instead of after the 5-minute timeout. The chart's ClusterRole already granted `list` and
`watch`, so there is no RBAC change.

## 2026-11-05 — the login response names its strategy

The portal has to decide whether to offer a step-up before it redirects anyone, and it
had no record of how a person signed in. `/oidc/stepup` couldn't answer that: it reads
no session, so it can only refuse after the redirect. Every login response now carries
`strategy`, in `/strategies`' terms. Authn doesn't bind a step-up to the session: someone
with an IdP account can complete one whatever session they hold, and the credential
belongs to that IdP identity. That grants nothing they didn't already prove, and the
admission policy still enforces the gate, so the portal compares usernames and discards
a mismatch.

## 2026-11-04 — outbound calls refuse redirects

oasgen-provider measured, in its own client (#401), that net/http keeps `Authorization`
on a redirect to a subdomain or another port. A 307/308 also resends the body to any
host. authn's own outbound calls all carry credentials and all followed redirects by Go's
default: the token exchange (client secret, code, verifier), UserInfo (the user's token),
discovery, and snowplow (authn's JWT and the user's token). Diego chose to refuse
redirects on all four. They now share `outbound.Client()`, and each test drives a real
redirect and asserts that the target received nothing.

## 2026-11-04 — basic auth compares passwords in constant time

`/basic/login` compared `password != string(pwd)`, so the time to refuse a guess grew with
how much of it matched. It now hashes both sides to SHA-256 and compares them with
`subtle.ConstantTimeCompare`. An unknown user costs the same comparison, against a fixed
value. Diego chose this over also accepting bcrypt hashes. The stored format is
unchanged, so installer has nothing to migrate. Still open: a known user costs a Secret
read that an unknown user doesn't (gotchas).

## 2026-11-04 — the RESTAction token leaves the URL

authn resolved a `restActionRef` with `GET /call?…&extras={"token":"<the user's IdP access
token>"}`, unescaped, so the token sat in every URL a gateway logged, and in authn's own
trace spans when tracing was on. It also read snowplow's error body twice, so a refusal or
a timeout reached the log as an empty string. snowplow confirmed that `POST /call/read`
takes the extras in the body, in every live version (since 1.12.28), and that snowplow
itself records no query. authn now sends the token there, and a snowplow failure is `500`
`RESTActionFailed` carrying snowplow's code and reason.

Diego first chose to delete the `LegacyResolve` fallback as well, which copies the
RESTAction and its endpoint Secrets with the user's token written in. Reading the
krateo-saas installer then showed `github-oauth-restaction` has no `${ .token }` header,
so it works only through that copy. The fallback stays, logged at warn on every use, and
goes once the RESTActions carry the header and installer confirms nothing falls back.

## 2026-11-04 — /oauth/login forwards the PKCE verifier

PKCE is the client's to add: authn is stateless between the redirect and the exchange, so
the portal generates the verifier, puts the `code_challenge` on the authorization URL and
sends the verifier back in `X-Code-Verifier`. `/oidc/login` and `/oidc/stepup` forwarded it;
`/oauth/login` didn't, so once the portal added PKCE every OAuth (GitHub) login would have
been refused as `AuthorizationCodeRejected`. frontend found that the portal sends no PKCE at
all. That matters even though authn is a confidential client: authn redeems any code posted
to it with its own secret, so a code intercepted from the victim's browser can be traded at
authn for the victim's credential. PKCE closes that. The portal enables it on OAuth flows
once a release with this fix is pinned.

## 2026-11-04 — a wrongly typed OIDC claim is refused, not a dropped connection

`doLogin` read ID-token and UserInfo claims with unchecked type assertions. An IdP sending
`"groups":"devs"`, a numeric `email` or a `null` `name` panicked the request. net/http
recovered and closed the connection without answering, so the portal saw "authn
unreachable", and nothing was logged as a failed login. Diego chose typed reads, with no
panic-recovery middleware that could hide the next one. A wrongly typed ID-token claim is
`403` `IDTokenInvalid`, a wrongly typed UserInfo field `500` `UserInfoFailed`, and `null` counts
as omitted (OIDC Core §5.1). UserInfo's status code is now checked and its body closed.

## 2026-11-04 — oidc and oauth logins answer the failure contract; no more 417

The oidc and oauth logins were the last routes outside the failure contract. A missing or
unreadable config answered `417` without a cause, and an authorization code the IdP refused
(expired, reused, wrong PKCE verifier) answered oidc `500`: a caller's mistake logged at
error, as if authn had broken. Diego chose to split the exchange by the token endpoint's
OAuth `error`: `invalid_grant` (and GitHub's `bad_verification_code`) is `403`
`AuthorizationCodeRejected`, anything else `500` `TokenExchangeFailed`, with the IdP's own
answer kept to the log. A missing config is `404` `OIDCConfigNotFound` /
`OAuthConfigNotFound`, like LDAP's. Every `400` gained a cause (`MissingConfigName`,
`MissingAuthorizationCode`, `InvalidRequestBody`), and a non-`2xx` `Status` now always says
`Failure`: `400` and LDAP's `300` said `Success`. frontend confirmed the portal never
branched on `417`.

## 2026-11-04 — OIDCConfig `allowedGroups`: admit only members

An OIDC login used to admit everyone the IdP authenticated; only RBAC limited what they could
do. For child platforms signing their owner in through the parent's Keycloak, Diego chose a
gate in authn as well, as defence in depth. `spec.allowedGroups` admits a user only if their
final groups include one of its entries. Everyone else gets `403 GroupNotAllowed` at
`/oidc/login` and `/oidc/stepup`, and nothing is minted. The check runs after the RESTAction
and after reserved `krateo:loa:` groups are stripped, so a step-up group can never be what
admits someone. Empty or omitted keeps today's behaviour. CRD change (authn-crds).

## 2026-11-03 — /health reports the version actually running

`GET /health` answered `{"name":"auth","version":""}` on every cluster: nothing stamped
`main.Version` at build time, so the endpoint documented to identify the running build
couldn't. A live read on 057 and demo found it while confirming their authn version. The
release build now passes the tag and commit (`release-tag.yaml` → `build_args`), and the
Dockerfile injects them with `-ldflags -X main.Version / main.Build`. A build without
them, such as a PR validation or a local build, reports `dev`.
## 2026-11-03 — `/strategies` answers `application/json`

`GET /strategies` set `Content-Type` after `WriteHeader(200)`, so the header was dropped and
Go sniffed the body as `text/plain`, although it is a JSON array. installer's pre-roll smoke
baseline caught it on 057 and demo. `TestSmokeAnswers` had passed, because it read the
recorder's live header map (`rec.Header()`) instead of the headers actually sent
(`rec.Result().Header`). Both are fixed. The surface tests now read sent headers, so a
header set too late fails them.

## 2026-11-03 — LDAP users get their groups

The LDAP login looked up a user's groups with a hardcoded filter,
`(uniquemember=uid=<username>,dc=example,dc=com)`, so in any directory not laid out
exactly like that the search matched nothing (#72). The login still succeeded, with no
groups: the certificate's `O=` and the JWT's `groups` were empty, and group-based RBAC
failed later as a "permission denied" nobody could trace. The new optional
`LDAPConfig` `spec.groupSearch` sets the search's `baseDN` (default `spec.baseDN`), its
`filter`, a Go template over the user's escaped `.DN` and `.Username` (default
`(|(member={{.DN}})(uniqueMember={{.DN}}))`, which covers groupOfNames, Active Directory
and groupOfUniqueNames), and the `nameAttribute` naming each group (default `cn`; an
entry without it is skipped instead of becoming an empty group). A filter that isn't a
usable template is a `500` `LDAPConfigInvalid`, found before authn connects to the
server. The user's groups are now exactly what the search finds, each once; the user
entry's `ou` values, which used to be its groups whenever it had any, are no longer
read. authn no longer asks the directory for password hashes: the user search requested
`userPassword` (and `memberof`, `ou`, `o`) though nothing read them, so a bind DN allowed
to read hashes received the user's on every login. It now asks only for `uid`, `cn` and
`mail`.

**Behaviour change:** deployments that relied on a user's `ou` values as groups must
bind RBAC to real directory groups, or set a `groupSearch.filter` that returns them.
A directory laid out as the old filter assumed (users at
`uid=<name>,dc=example,dc=com`, groups listing them in `uniqueMember`, users without
`ou`) gets the same groups as before. The default also matches `member`, so there a
group that lists the user only in `member` now counts too.

## 2026-11-02 — Basic and ldap tell refusals from their own failures

Basic and ldap answered `403` for anything that went wrong, so an unreachable LDAP server
or an apiserver error reading a `User` looked like a wrong password, and logged at warn.
Both now follow the failure contract of `/serviceaccount/login` and `/oidc/login`: each
failure is a `Status` with a cause, `401`/`403` when the caller is refused, `500` when
authn failed. The causes are listed in [api](./api.md). An unknown user, an unusable
user name and a wrong password are one response, `403` `InvalidCredentials`, byte for byte:
before, an unknown basic user's `403` carried the apiserver's not-found text and an
unknown LDAP user got `404`, so a caller could probe which usernames exist. The real
reason is now only in the warn log line. Besides the new `500`s, three answers changed: a
missing basic `Authorization` header is a JSON `Status` (`MissingCredentials`) instead of a
plain-text `401`, an unknown LDAPConfig is `404` `LDAPConfigNotFound` instead of `417`,
and an unknown LDAP user is `403` instead of `404`. An ambiguous LDAP user keeps its
`300`. The oauth login no longer writes a second response after a RESTAction answer it
can't parse.

## 2026-11-02 — Refused logins are logged at warn

Every failed login was logged at error, so a caller with an expired token or a wrong
password looked like an authn failure, and error-level alerts fired on it. The level now
follows the status code: a refusal of the caller (`401`/`403`, other `4xx`) is logged at
warn, authn's own failure (`5xx`) stays at error. `status.LogFailure` picks the level from
the code `status.FromError` answers with, and adds `code` and `cause` to the line; the
step-up, serviceaccount and OIDC login refusals use it. Basic, ldap and the `400`s for a
missing `name` or code log at warn directly. No response changed. Basic and ldap still
answer `403` when the apiserver or LDAP server is unreachable, so those log at warn until
they get a `5xx`.
## 2026-11-02 — The signing key can be rotated without signing everyone out

The JWT docs described rotation as publishing the old and new keys together, but authn's
JWKS served exactly one key. Rotating was a hard cutover: every outstanding token failed
at once. In permissive validation nobody noticed. Once agentgateway enforces (roadmap A3),
every signed-in user would be cut off. `jwt.previousKeys` (`JWT_PREVIOUS_KEYS`) now
publishes retired keys next to the current one, for verification only. The current key
comes first in the JWKS. A retired key is mounted from its Secret, as the private key or
just its public half. Misconfiguration fails at boot rather than silently dropping a key.
Tests sign tokens with the old and new keys and verify both through plumbing's
`JWKSKeySource`, the client snowplow uses. A key no longer published verifies nothing.

## 2026-11-01 — Expired step-up credentials are deleted

`<user>-clientconfig-stepup` lives about 15 minutes and is never renewed, but nothing removed
it, so expired keys and certificates stayed at rest, one per user who ever stepped up (found
by acmp's end-to-end run). The replica holding the `authn-cert-renewal` Lease now sweeps
them every 5 minutes. It deletes only Secrets named like a step-up credential, whose
certificate (read from the Secret, not an annotation) has been expired for 5 minutes, and
only if they are still the object it read. A step-up that rewrote the Secret in the
meantime keeps its credential. Unreadable certificates are left in place and logged.
Session Secrets are never touched. Verified on kind: an expired step-up Secret is deleted
at the first pass; a valid one and an expired session Secret stay.

## 2026-10-31 — The HTTP surface is pinned and checked for leaks

`main.go` built the routes inline, so nothing tested the surface as a whole. Route
construction moved to `buildRoutes` (`go/authn/routes.go`), and `TestPublicSurface`:
- pins the list of routes, so a new route fails CI until it is reviewed;
- runs every route against a fake apiserver whose Secrets all hold canary key material,
  passwords and client secrets, with every method and the inputs a caller without valid
  credentials can send: no credentials, wrong or junk ones, and real identity names (792
  requests). It fails if any response body or header carries a canary, a private key or
  `client-key-data`, or if a credential is minted.

`TestPublicSurfaceGuardCatchesALeak` adds a route that returns a stored credential and
checks that the guard flags it, so the guard can't silently stop working.
`TestJWKSIsPublicOnly` checks the JWKS carries only `kty`, `use`, `alg`, `kid`, `n`, `e`.
Audit of the remaining routes: `/strategies` returns names, graphics, client IDs and
authorization URLs only; CORS answers a literal `*`, which browsers refuse for credentialed
requests.

## 2026-10-31 — The OIDC `authCodeURL` scope has no trailing space

With an empty `additionalScopes`, `authCodeURL` sent `scope=openid email profile ` with a
trailing space. Keycloak accepts it, but it isn't a well-formed space-separated scope
list. The scope is now normalized: single spaces, nothing leading or trailing.

## 2026-10-31 — `GET /info` is removed

`GET /info?name=<user>` returned the stored `AuthInfo` of an identity. No caller exists:
every team that owns a consumer of authn checked its code, charts, scripts and docs, and
none calls it. Credentials are read in-cluster from the `<user>-clientconfig` Secrets,
under RBAC, so the route is removed, together with the storage layer's read path that only
it used. Requests to `/info` now get `404`.
## 2026-10-31 — `/strategies` tells the portal how to ask for a step-up

The portal had no way to learn which OIDC providers support step-up, or which `acr_values`
to request: those live in `OIDCConfig.spec.stepUp`, which only authn reads. An oidc entry
whose `spec.stepUp` is valid now carries `extensions.stepUpAuthCodeURL`, the complete
step-up authorization request, plus `stepUpPath`, `stepUpAcrValues` and `stepUpMaxAge`.
authn builds the URL (the login `authCodeURL` with `acr_values` and `max_age` set, so the
IdP re-authenticates instead of authn answering `StaleAuthentication`), because the portal
composing it would stack string operations on a URL whose shape it doesn't own. No IdP
values are hardcoded in the portal. The keys are added only when step-up is enabled, so existing
clients see no change. `spec.stepUp.acrValues` now also refuses an empty value, which would
have matched an ID token with no `acr` at all, and a value containing whitespace, which
can't be sent in the space-separated `acr_values`. Both answer `StepUpMisconfigured`.
## 2026-10-31 — The OIDC `authCodeURL` state is printable; Keycloak refused 1 login in 8

`authCodeURL` built `state` from 32 raw random bytes. The URL therefore carried binary
bytes, and about 1 in 8 times a NUL (`%00`), which Keycloak 26 answers with `400`. A
real-Keycloak test of step-up found it. The portal hid it until now because it replaces
`state` with its own; any client using `authCodeURL` as is failed about 1 login in 8. `state`
is now 32 random bytes, base64url-encoded without padding. authn still neither stores nor
checks `state`: a client that wants CSRF protection sets and verifies its own.

## 2026-10-31 — A login that can't sign its token answers 500, never an empty 200 (#48)

When the JWT couldn't be signed (for example, an empty key ID), `encode.Success` returned
before writing anything. The basic, ldap, oauth and oidc logins ignored the error, so the
caller got an empty `200`: a "successful" login with no body and no token. `encode.Success`
now answers the request itself in that case, with `500` and cause `IssuanceFailed`. Every
current and future login is covered, and each handler logs the error.

## 2026-10-31 — The ServiceAccount CRD drops the `serviceaccount` category (#34)

`serviceaccounts.serviceaccount.authn.krateo.io` declared the categories `krateo`, `authn` and
`serviceaccount`. kubectl expands a category before it looks up a resource name. So on any
cluster with authn's CRDs, `kubectl get serviceaccount <name>` read authn's ServiceAccount
instead of the core one, and answered NotFound for a ServiceAccount that exists. Scripts that read
"not found" as "gone" then decided wrongly. The category is gone; `kubectl get krateo` and
`kubectl get authn` still list it. The fix is EdmondDantes21's branch (Oct 22), rebased onto main.

## 2026-10-30 — Step-up login (#49)

`POST /oidc/stepup` issues a short-lived credential carrying `krateo:loa:2` to an OIDC
login that proves a higher assurance level, so admission policies can require a fresh,
stronger login for destructive operations (acmp; first consumer: the OpenStack
decommission guard).

- **Proof.** The validated ID token's `acr` must be in `spec.stepUp.acrValues`, and its
  `auth_time` must be within `maxAge` (default 5m), so an old SSO session at the right
  level is not enough.
- **Credential.** It is stored as `<user>-clientconfig-stepup`, beside the session
  credential and never in place of it. Its `ttl` defaults to 15m (minimum 10m) and it
  is never renewed. The JWT's groups carry `krateo:loa:2`; snowplow keys on that group
  to pick the step-up Secret (snowplow#994). No `loa` claim was added, because plumbing's
  JWT signs only username and groups, and one marker everywhere is simpler.
- **Naming.** The Secret name ends in `-stepup` because an infix name
  (`<user>-stepup-clientconfig`) let user `bob-stepup`'s session collide with `bob`'s
  step-up.
- **CSRs.** Every issuance now gets its own CSR (`generateName`), deleted once used.
  Before, the CSR was named after the user and deleted and recreated, so a normal login
  and a step-up for one user could destroy each other's request.

## 2026-10-30 — Go tests run on main too, so release commits carry them

installer's pin gate refused 0.29.0: the tagged commit had no test check-run. The tests
had run with `-race` on #51's PR head, whose tree is byte-identical to 0.29.0's. But PR CI
triggers only on `pull_request`, and a release tags the squash commit on `main`.
`checks-main.yaml` now runs the same shared go-checks job on every push to `main`, so
every release commit has its own `checks / test`. The release runbook says to tag only
when it is green.

## 2026-10-29 — OIDC login accepts a PKCE verifier (#49)

An OIDC login can now use PKCE (RFC 7636). The client that starts the authorization
request adds `code_challenge`, then sends the verifier to `/oidc/login` in
`X-Code-Verifier`, and authn forwards it as `code_verifier` on the code exchange.
Without the header nothing changes. CORS allows the new header. This is groundwork for
the step-up login (#49), whose browser flow uses PKCE.

## 2026-10-29 — `krateo:loa:*` groups are reserved to authn (#49)

Step-up logins will mark their credential with the group `krateo:loa:2`, and admission
policies will require it for destructive operations. To make that group unforgeable,
every identity authn builds now drops `krateo:loa:*` groups, whatever the strategy or
source:
- IdP claims;
- RESTActions;
- basic `User`;
- `ServiceAccount` mappings.

Each drop is logged. The generator also refuses to mint any identity that still carries
one. Groups that merely look similar, such as `krateo:loader`, are untouched.

## 2026-10-29 — OIDC login validates the ID token (#50)

`/oidc/login` used to trust whatever the token endpoint returned: it base64-decoded the ID
token and read its claims without checking who issued it, for whom, or until when. It
now checks `iss`, `aud`/`azp` and `exp` first, as OIDC Core §3.1.3.7 requires. It does
not check the signature, which §3.1.3.7 allows for a token fetched back-channel over TLS
with client authentication.

**Breaking for hand-configured OIDCConfigs.** The expected issuer comes from
`discoveryURL`, or from the new `spec.issuer`. A config with neither refuses every login
(`500` `IssuerUnknown`), and authn names it in a startup warning. Fix:

```yaml
spec:
  tokenURL: https://kc.example/realms/krateo/protocol/openid-connect/token
  issuer: https://kc.example/realms/krateo   # exactly the ID token's iss
```

Before upgrading, list the configs that need `issuer`. Use the full resource name: with a
wrong group (e.g. `oidc.krateo.io`), kubectl reports that the *resource type* doesn't
exist, which reads like "no OIDC here" but isn't.

```sh
kubectl get oidcconfigs.oidc.authn.krateo.io -A -o json | jq -r '.items[]
  | select((.spec.discoveryURL // "") == "" and (.spec.issuer // "") == "")
  | "\(.metadata.namespace)/\(.metadata.name)"'
```

An empty output means nothing to change. authn also names any such config in a warning at
startup.

A config with a `discoveryURL` keeps working unchanged, and authn now reads the discovery
document on every login, even when all endpoints are set. Split out of the step-up work
(#49), which builds on it.

## 2026-10-29 — `/serviceaccount/login` failures name their cause and their side

core-provider's `ApiResolved` condition (core-provider#251) needs to say why a cdc could
not authenticate without parsing English. Every serviceaccount login failure now carries a
stable token in `details.causes[0].reason`, Kubernetes `StatusDetails`-style. The status
code says whose failure it is.

Refusals of the caller (`401`/`403`):
- `MissingBearer`
- `TokenNotAuthenticated`
- `AudienceMismatch`
- `NotAServiceAccount`
- `NoMapping`
- `AmbiguousMapping`

Failures of authn (`500`, `InternalError`):
- `TokenReviewFailed`
- `MappingLookupFailed`
- `IssuanceFailed`

Status codes changed:
- A failed TokenReview call and a failed mapping list used to be `403`. They are now
  `500`: a client that classifies on the code would otherwise send an operator to check
  audiences and mappings when the fault was authn's own dependency (core-provider's
  review).
- A TokenReview `status.error` (invalid or expired token) is the apiserver's verdict on
  the caller, so it is `TokenNotAuthenticated` with that error in the message.
- The missing-bearer `401` is now a JSON `Status` like every other failure; it used to be
  plain text.
- A JWT that could not be signed used to produce an empty `200`. It is now `500`
  `IssuanceFailed`, because `encode.Success` builds the whole body before writing.

## 2026-10-29 — authn can run more than one replica (#45)

0.28.0 renewed `authn-clientconfig` in a loop that assumed a single replica: its CSR is
named after the username and recreated on conflict, so two replicas would delete each
other's requests.

Now only the replica holding the `authn-cert-renewal` Lease does authn's own-identity
work: issuing, renewing and the identity backfill. Every replica serves logins, so
`replicaCount > 1` and autoscaling are safe. A crashed leader is replaced within 15s.
The chart's Role gains `get/create/update` on `leases`.

## 2026-10-29 — clientconfig Secrets record their strategy and groups (#42)

Tenant onboarding (a Kyverno policy) fires on every `<user>-clientconfig` Secret, but nothing
on them told a tenant from a platform admin or from authn's own identity. So every
clientconfig authn writes now carries:
- `authn.krateo.io/strategy` (`self` for authn's own identity);
- `authn.krateo.io/groups`: the certificate's `O=`, newline-separated, because group names
  can contain commas.

A startup backfill stamps older Secrets. Groups come from the certificate; the strategy is
set only where it can be proven, otherwise it's `unknown`. The policy decides from these
facts, so there's no hand-kept list of names.

## 2026-10-29 — `/serviceaccount/login` no longer returns the kubeconfig (#36)

The serviceaccount login returned the full kubeconfig in `data`, including
`client-key-data`, a private key. The natural first step when integrating, printing the
response, wrote that key into a terminal ([#36](https://github.com/krateo-platformops/authn/issues/36)).

**The fix:** the response now carries only `accessToken`, `user` and `groups`. authn still
mints the identity and writes `<username>-clientconfig`, which plumbing endpoints,
snowplow and bff read from the Secret.

**Fleet check before the change:** across 56 repos, the four clients of this endpoint
decode `accessToken` only:
- core-provider
- core-provider's cdc
- rest-dynamic-controller
- snowplow

The human strategies are unchanged.

## 2026-10-29 — client certificates: authn's own is renewed, login JWTs are clamped (#28)

Fixes [#28](https://github.com/krateo-platformops/authn/issues/28), ported from
PR #76 of the legacy pre-fork repository (by EdmondDantes21), which never reached this repo:
- `authn-clientconfig` was written once at boot and never renewed. A pod that outlived
  its certificate failed every RESTAction call with `x509: certificate has expired`
  until restarted.
- The signer may grant far less than requested: OpenShift caps at 720h and rotates its
  CA every 30 days.

What changed:
- authn now reads the **granted** `NotAfter` and annotates every Secret with it.
- It renews its own certificate in the background at a fraction of the granted lifetime.
- Every login JWT, including `serviceaccount`, is clamped to its certificate's real
  expiry, so a session can no longer outlive its credential.
- New knobs: `AUTHN_SERVICE_CRT_EXPIRES_IN`, `AUTHN_CRT_RENEWAL_THRESHOLD`,
  `AUTHN_CRT_RENEWAL_ENABLED`.

See [certificate-renewal](./certificate-renewal.md). Verified on kind; capped-signer
distributions are still unverified.

## 2026-10-29 — intra-service auth: §6 open questions closed

The [decision record](./design/kubernetes-intra-service-auth.md) still listed token
audience & naming, JWT lifetime and the endpoint shape as open, although 0.23.0 had already
settled them. The record now matches the shipped code:
- one global audience, `authn`, configurable per install;
- the username is the mapping's `metadata.name`;
- `POST /serviceaccount/login`;
- the JWT lives as long as the client certificate (`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`), with no
  per-mapping TTL.

Revocation is mapping deletion for new exchanges, plus RBAC unbinding or expiry for
credentials already issued. Multi-cluster is decided as **target-local authn**: a service in
a remote target exchanges its token with an authn in that target, because TokenReview is
cluster-local. Bootstrap ordering is resolved as caller-side degradation, which both shipped
callers already do (core-provider's cdc and snowplow's prewarm seed). §6 is now fully closed.

## 2026-08-07 — adopted the Krateo Documentation Standard

This bundle: root `docs/` core set + `examples/` + thin README. The internals corpus
(architecture/behavior/gotchas) was re-verified line-by-line against the source: the
`main.go` and `routes.go` citations had drifted since the OpenTelemetry
instrumentation landed (the docs predated it entirely), the `oidc/support.go`
citations had shifted ~8 lines, and the OAuthConfig type was attributed to the base
`apis/authn/oauth/types.go` while the served kind (with `restActionRef`/`graphics`)
lives in `apis/authn/oauth/v1alpha1/`. `docs/llms.txt` still routed the deployment
view to a long-dead separate chart repo — the chart has lived in `helm/` since the
monorepo fold. All re-grounded; the intra-service-auth design doc is now a living
decision record (`status: implemented`).

## 2026-08-03/04 — 0.26.0: the monorepo fold + org independence

The separate chart repo was collapsed into `helm/` (one version line: image + both
charts ship from one tag), the app moved into `go/authn/`, and Go module identity
migrated to `github.com/krateo-platformops/authn`; CI moved to the org's shared
reusable workflows (multi-arch image build, Go checks + CRD-drift guard, security).
Lesson paid for en route: the migration was first tagged `v0.25.0` — the `v` prefix
matches no release-workflow trigger, so it shipped nothing; `0.26.0` is the release
that followed. Tag without `v`, always ([release](./release.md)).

## 2026-06-25 — gated, default-off OpenTelemetry (#9, #10)

Traces + metrics + trace/log correlation landed behind the `OTEL_ENABLED` master gate
(per-signal `OTEL_TRACING_ENABLED` / `OTEL_METRICS_ENABLED` overrides, OTel-Go
v1.44). Off-path is byte-identical to the un-instrumented service; `/health` is
filtered out of tracing. The CORS allowlist grew the W3C trace-context headers
(`traceparent`/`tracestate`/`baggage`) so the browser→authn hop can carry a trace.

## 2026-06-20 — 0.23.0: the `serviceaccount` login strategy

Kubernetes intra-service auth shipped as designed
([decision](./design/kubernetes-intra-service-auth.md)): a backend service exchanges
its own projected, audience-bound SA token (validated via the TokenReview API)
against a `ServiceAccount` allowlist CRD for the same JWT + kubeconfig human users
get — no signing-key sprawl, RBAC stays standard Kubernetes on the mapping's groups.
The chart gained `tokenreviews:create` + allowlist-read RBAC (#25). First consumers:
core-provider's cdc and snowplow's prewarm seed.

## Earlier (the 0.22.x line and before)

The five-strategy shape settled: per-strategy config CRDs, the CSR-minted per-user
client-cert kubeconfig as the one identity output, RESTAction-based identity
compilation for OAuth2/OIDC via snowplow, and the crds-subchart versioning reversal
(CRD chart released at the main chart's tag — hand-copied CRD drift once broke portal
login). Release notes: GitHub Releases.
