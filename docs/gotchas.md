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

## Existing CSR is deleted, not reused
If a CSR with the computed name already exists, the generator **deletes and
recreates** it (`config/gen.go:41-55`) rather than reusing the prior cert. Repeated
logins for the same user churn CSR objects; concurrent logins for the same user can
race on that delete/recreate.

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

## LDAP TLS skips verification
With `spec.tls: true`, the LDAP `StartTLS` call uses `InsecureSkipVerify: true`
(`internal/routes/auth/ldap/support.go:70`). TLS here gives transport encryption but
**no certificate validation** — it does not protect against a MITM with a forged
cert.

## OIDC ID token is decoded, not cryptographically verified
`decodeJWT` base64-decodes the ID token payload and JSON-parses the claims
(`oidc/support.go:210-231`); it does **not** verify the signature, issuer, audience,
or expiry. Trust rests on the TLS channel to the token endpoint and the preceding
code exchange, not on token verification. Treat any field copied from the ID token
accordingly.

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
