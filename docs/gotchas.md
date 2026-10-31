---
type: Runbook
title: authn — gotchas (internals)
description: Real runtime pitfalls, each grounded in the code/config at this tag — RBAC traps, routing, OIDC token handling, the snowplow URL quirk.
resource: ghcr.io/krateo-platformops/authn
tags: [internals, pitfalls, code-traced]
timestamp: 2026-08-07T00:00:00Z
---

# authn — gotchas

Real runtime pitfalls, each grounded in the code/config at this tag (paths relative
to `go/authn/`).

## Routing is exact-match — no trailing slash, no prefix
`routes.Serve` compares `req.URL.Path == route.Pattern()` exactly
(`internal/routes/routes.go:22`). `/basic/login/` (trailing slash) or any sub-path
returns `404`; hitting a registered path with the wrong verb returns `405` with an
`Allow` header (`routes.go:47-51`). There is no router middleware to normalize paths.

## `/list` is defined but not served
`internal/routes/list.go` implements a `/list` route, but it is **not** appended to
the route table in `main.go`. Don't document or rely on `/list` as a live endpoint at
this tag — only the eight routes wired in `main.go:169-233` are served.

## CSR RBAC is mandatory — and broad
Every login mints a client cert via the Kubernetes CSR API and **self-approves** it
(`config/gen.go:36-68`). Without the CSR ClusterRole (create/get/list/watch/approve/
delete/update on `certificatesigningrequests` + `approve` on signer
`kubernetes.io/kube-apiserver-client`) every login fails at cert generation. The
chart installs and binds it (`helm/authn/templates/clusterrole.yaml`); if you deploy
from the dev manifests instead, note `manifests/rbac.csr.yaml` binds namespace
`demo-system` — bind authn's real ServiceAccount/namespace, or approval silently 403s.

## Every issuance gets its own CSR, deleted once used
The CSR is created with `generateName: <username>-`, so the apiserver adds a random
suffix (`kube.NewCertificateSigningRequest`). authn deletes it as soon as the
certificate is read (`config/gen.go`). Concurrent logins for one user, such as a normal
login and a step-up, or two browser tabs, each get their own request. Before #49 the
CSR was named after the user and an existing one was deleted and recreated, so
concurrent logins raced. When you look for a user's CSR, match the `<username>-`
prefix, not the bare name. A CSR left behind (e.g. authn crashed mid-login) is
garbage-collected by the apiserver within an hour. authn's own certificate renewal
doesn't use this path: it goes through plumbing's `signup`, which names the CSR
`authn`, and its single writer is the Lease holder.

## A certificate's notBefore is 5 minutes before its issue
The Kubernetes CSR signer backdates `notBefore` by 5 minutes to absorb clock skew, so
`notAfter - notBefore` is the granted lifetime **plus 5m**: a 20m step-up certificate
reads as 25m. Measure a lifetime from issue time (the login JWT's `iat`) to `notAfter`,
not from `notBefore`.

## A step-up credential lives beside the session, never in it
`POST /oidc/stepup` writes `<user>-clientconfig-stepup`, never `<user>-clientconfig`.
The name ends in `-stepup`, so no username's session Secret can collide with
another username's step-up Secret, and listings by the `-clientconfig` suffix (like
the identity backfill) skip it. It is not renewed: when it expires, the user steps up
again.

## An IdP can answer a step-up from SSO with an old `auth_time`
`acr_values` alone doesn't make the IdP re-authenticate. Keycloak's level-2 condition
has its own max age: when it is longer than `spec.stepUp.maxAge`, a step-up within it
completes silently from the SSO session and returns the earlier `auth_time`, and authn
refuses it as `StaleAuthentication`. Send `max_age=<maxAge in seconds>` on every step-up
request, not only after a refusal. `stepUpAuthCodeURL` in `/strategies` already carries it.
On Keycloak, keep the level-2 condition's max age at 0 (or at most `maxAge`). Then an
SSO step-up asks only for the second factor and returns a fresh `auth_time`. Verified on
Keycloak 26.4: realm `acr.loa.map` `{"silver":1,"gold":2}`, a browser flow with
conditional "Level of Authentication" subflows (level 1 password, level 2 OTP), and
the default `acr` client scope.

## authn's own-identity work runs on the Lease holder only
Issuing and renewing `authn-clientconfig`, and the identity backfill, run only on the
replica holding the `authn-cert-renewal` Lease (`coordination.k8s.io`) in authn's
namespace (`go/authn/internal/leader`). Its CSR is named after the username (`authn`)
and an existing CSR is deleted and recreated (above), so two writers would delete each
other's in-flight requests. Every replica serves logins, so `replicaCount > 1` and
autoscaling are safe.

The Lease needs `get/create/update` on `leases`, which the chart's Role grants. Without
it, no replica ever leads and authn's own certificate is never issued or renewed. Check
which replica leads with `kubectl -n <ns> get lease authn-cert-renewal`. A crashed leader
is replaced within 15s; a graceful shutdown releases the lease at once.

Set `AUTHN_CRT_RENEWAL_ENABLED=false` only if you accept that the certificate expires in
place until a restart ([certificate-renewal](./certificate-renewal.md)).

## The requested certificate lifetime is a wish
The signer grants `min(requested, --cluster-signing-duration, signer CA remaining
life)`. OpenShift caps it at 720h with a 30-day CA rotation, so a 24h login certificate
can come back shorter. The login JWT is clamped to the **granted** `NotAfter`, so on a
capped signer sessions end earlier than `AUTHN_KUBECONFIG_CRT_EXPIRES_IN` suggests.
That is intended. Look for the `warn` logged when the grant is under 90% of the request.

## Config CRs live in the operator namespace — everywhere
Every lookup (`User`, `ServiceAccount` mappings, `LDAPConfig`, `OAuthConfig`,
`OIDCConfig`) lists/gets **only the operator namespace**
(`util.GetOperatorNamespace()`, from `POD_NAMESPACE` —
`internal/helpers/kube/resolvers/*.go`). A CR created in any other namespace is
invisible: the strategy won't appear in `/strategies` and logins against it fail.

## Intra-service auth needs `create tokenreviews` RBAC
`/serviceaccount/login` validates the caller's SA token by creating a `TokenReview`
(`serviceaccount/login.go:118-136`). authn's ServiceAccount must be granted `create`
on `tokenreviews.authentication.k8s.io` — this is **separate** from the CSR RBAC
above (the chart grants both). Without it every intra-service login fails at the
TokenReview call (returned to the caller as `403`).

## Intra-service SA tokens must be audience-bound
The strategy submits the TokenReview with the configured audience (default `authn`,
`--serviceaccount-audience` / `AUTHN_SERVICEACCOUNT_AUDIENCE`) and rejects the token
unless that audience is echoed back in `status.audiences`
(`serviceaccount/login.go:134-136`). A plain default-audience SA Secret or a token
minted for the kube-apiserver / another service will **not** authenticate — callers
must mount a **projected** token (`TokenRequest`) bound to authn's audience.

## Unmapped ServiceAccounts are rejected — and the mapping must live in the operator namespace
A TokenReview-authenticated SA still only exchanges if a
`serviceaccount.authn.krateo.io/ServiceAccount` CR's `spec.serviceAccountRef` matches
it; the CR's existence **is** the allowlist, and no match → `403`
(`resolvers.ServiceAccountForSA`, `resolvers/serviceaccount.go:19-58`). Two further
traps: (1) the mapping is looked up **only in the operator namespace** (see above),
so a mapping created elsewhere is invisible and the exchange is rejected; (2) if two
mappings reference the same SA, the lookup is **ambiguous and errors out** rather
than picking one. Note `metadata.name` is the issued *username* and need not equal
the SA name, so the mapping is matched by ref, not by name.

## The login response body carries a private key — never log it
A successful login returns the minted kubeconfig in `data`. Its `client-key-data` is
the PEM private key of the issued client certificate (`kube/config/types.go:37`,
`config/build.go:153`). The `accessToken` is a bearer credential as well. Callers,
intra-service ones most of all because they log into shared pipelines, must never log
or wrap the `200` body in an error. Error (non-`200`) bodies carry no secrets, so
quoting them in an error is safe. Keep it that way when changing `encode.*`.

## LDAP TLS skips verification
With `spec.tls: true`, the LDAP `StartTLS` call uses `InsecureSkipVerify: true`
(`internal/routes/auth/ldap/support.go:70`). TLS here gives transport encryption but
**no certificate validation** — it does not protect against a MITM with a forged
cert.

## OIDC ID token claims are validated, its signature is not
Since 0.29.0 (#50), `validateIDToken` (`oidc/idtoken.go`) checks `iss`, `aud`/`azp`
and `exp` before any claim is used. It does **not** verify the signature: trust in
the token's integrity rests on the TLS channel to the configured token endpoint and
the client-authenticated code exchange, which OIDC Core §3.1.3.7 allows. A
hand-configured OIDCConfig (no `discoveryURL`) must set `spec.issuer`, or every login
is refused with `IssuerUnknown`.

## `krateo:loa:*` groups are dropped from every identity source
Groups prefixed `krateo:loa:` are reserved: they record a step-up login's assurance
level (#49), and admission policies trust them. If an IdP groups claim, a RESTAction, a
basic `User` or a `ServiceAccount` mapping asserts one, authn drops it from both the
certificate and the JWT, and logs `dropped reserved groups asserted by the identity
source`. The guard is in `userinfo.NewDefaultUser`/`SetGroups`. As a backstop, the
generator refuses to mint any identity that still carries one. Don't name a real
group with this prefix: its members will lose it.

## OIDC groups never come from UserInfo
Missing `name`/`email`/`picture`/`preferred_username` claims trigger a UserInfo call,
but `groups` are read **only** from the ID token (`oidc/support.go:149-156`). An IdP
that returns groups only on UserInfo will yield a user with no groups (and therefore
no RBAC), unless a `restActionRef` supplies them.

## RESTAction enrichment can only set five keys
The `status` map snowplow returns may override exactly `name`, `email`,
`preferredUsername`, `groups`, `avatarURL` (`oidc/support.go:233-280`). `checkKeys`
rejects **any** other key via its `default` branch (`oidc/support.go:317-319`), which
flips the flow to `LegacyResolve`. A RESTAction that returns extra top-level status
fields will never take the fast path.

## LegacyResolve mutates the cluster mid-login
`LegacyResolve` **creates** a per-user copy of the RESTAction and each referenced
endpoint Secret, calls snowplow, then **deletes** them
(`restaction/resolver.go:68-186`). A login that crashes or is cancelled between
create and delete can leave orphaned `<name>-<email>` RESTActions/Secrets behind. It
also requires authn to have write/delete RBAC on `restactions` and Secrets, beyond
the read-only access the other paths need (the chart's Role grants it).

## Basic-auth password comparison is plaintext, non-constant-time
`validate` compares `password != string(pwd)` directly (`basic/login.go:122`) against
the raw Secret value — the password is stored in plaintext in the referenced Secret
and compared without a constant-time check.

## snowplow URL resolution has a quirk
The snowplow URL is built eagerly from `SNOWPLOW_SERVICE_HOST`/`PORT` **before**
flags are parsed, so when those env vars are unset it produces the literal
`http://:8081`; only then does it fall back to `URL_SNOWPLOW` (`main.go:63-72`). If
`SNOWPLOW_SERVICE_HOST` is empty but `SNOWPLOW_SERVICE_PORT` is set to something
other than `8081`, the fallback check (`== "http://:8081"`) misses and authn calls a
hostless URL. Set `URL_SNOWPLOW` explicitly to be safe.

## No boot without a signing key
authn signs asymmetrically with RS256 ([jwt-jwks](./jwt-jwks.md)) and fails fast at
startup — not per-request — if `JWT_KID` is empty or `JWT_SIGN_KEY_FILE` is
missing/unparseable (`main.go`): `log.Fatal` before any route is registered. The
chart makes the dependency structural: the Deployment mounts the `authn-jwt-signing-key`
Secret's PEM private key as a file. Rotating the key without changing `kid` (or vice
versa) makes previously issued tokens unverifiable against the new JWKS.

## Health gates on a flag flipped after listen
`/health` returns `503` until the goroutine sets `healthy=1` (`main.go:302`), and
flips it back to `0` on shutdown (`main.go:315`). It reflects process lifecycle only
— it does **not** check apiserver/snowplow/LDAP reachability, so a "healthy" authn
can still fail every login if its dependencies are down.
