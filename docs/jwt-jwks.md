---
type: Integration
title: authn — JWT signing & JWKS
description: How authn signs JWTs with RS256, publishes a JWKS, and how validators (Snowplow, agentgateway) consume it.
tags: [authn, jwt, jwks, rs256, security]
timestamp: 2026-08-10T00:00:00Z
---

# authn JWT signing & JWKS

authn issues JSON Web Tokens for the Krateo platform. It signs with **RS256** using
an RSA private key and publishes the matching public key as a **JWKS** so that any
validator — Snowplow, agentgateway, or a third party — can verify tokens without
sharing a secret.

## What a token looks like

- **Algorithm:** `RS256` (asymmetric). Symmetric `HS256` is no longer used.
- **Header:** carries a `kid` identifying the signing key (required by agentgateway).
- **Claims:** `username`, `groups`, `principal`, `iss: "krateo.io"`, `sub`, `exp`, `iat`, `nbf`,
  and `act` on a delegated token.
- **`principal`** is the kind of identity the token names, set from how it was obtained,
  never from the request: `human` for a person's sign-in (basic, LDAP, OAuth, OIDC,
  step-up), the `ServiceAccount` mapping's `spec.principal` for `/serviceaccount/login`
  (`agent`, `controller`, or `service` when it declares none), and `service` for authn's
  own token to snowplow. A delegated token keeps its subject's `principal`, and each
  `act` link carries its actor's. Validators read it with plumbing ≥ v1.34.0
  (`jwtutil.UserInfo.Principal`, and `ActorPrincipal()` for whoever is acting). A token
  from authn before 0.39.0 has none, which reads as `""`.
  No `aud`.

The signing itself lives in the shared `plumbing/jwtutil` library
(`CreateToken` / `Validate`); authn only supplies the key material and `kid`.

## Configuration

authn reads two settings at startup:

| Flag | Env | Meaning |
| --- | --- | --- |
| `--jwt-sign-key-file` | `JWT_SIGN_KEY_FILE` | Path to the PEM-encoded RSA **private** key. |
| `--jwt-kid` | `JWT_KID` | Key ID stamped into every token header and the JWKS. |

Both are required; authn exits at boot if the key file is missing/unparseable or
the `kid` is empty. The private key is read from a **file** (mounted from a Secret),
never passed as a raw env value. See [configuration](./configuration.md) for the
full Helm values (`jwt.signKeySecretName`, `jwt.signKeySecretKey`, `jwt.mountPath`,
`jwt.kid`).

## Creating the signing-key Secret

Generate an RSA keypair and store the private key in a Secret. authn derives the
public key (and the JWKS) from it at runtime — you only ever store the private half.

```sh
# 1. Generate a 2048-bit RSA private key.
openssl genrsa -out private.pem 2048

# 2. Create the Secret in authn's namespace.
kubectl create secret generic authn-jwt-signing-key \
  --namespace krateo-system \
  --from-file=private.pem=./private.pem
```

The Helm chart mounts this Secret at `/etc/authn/jwt/private.pem` and sets
`JWT_SIGN_KEY_FILE` accordingly. Relevant `values.yaml`:

```yaml
jwt:
  signKeySecretName: authn-jwt-signing-key  # Secret name
  signKeySecretKey: private.pem             # key within the Secret + mounted filename
  mountPath: /etc/authn/jwt                 # mount directory
  kid: krateo-authn-key-1                   # stable key ID (kid)
```

> Keep `kid` stable for the life of the key. Changing the key without changing the
> `kid` (or vice versa) makes previously issued tokens unverifiable.

## The JWKS endpoint

authn serves the public key set at:

```
GET /.well-known/jwks.json
```

on its normal service port (default `8082`) — no separate service or route change
is required. The response is a standard JWKS:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "krateo-authn-key-1",
      "n": "<base64url-modulus>",
      "e": "AQAB"
    }
  ]
}
```

Quick check once deployed:

```sh
kubectl -n krateo-system port-forward svc/authn 8082:8082
curl -s http://localhost:8082/.well-known/jwks.json | jq
```

## Consuming the JWKS

### agentgateway (remote JWKS)

Point agentgateway at the endpoint via `jwks.remote` so it refetches on a cadence
(supports key rotation). The `issuer` matches authn's `iss`; omit `audiences`
because authn emits no `aud`.

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: authn-jwt
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: mcp
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
      - issuer: "krateo.io"
        jwks:
          remote:
            backendRef:
              name: authn            # authn's Service
              kind: Service
              namespace: krateo-system
              port: 8082
            jwksPath: /.well-known/jwks.json
            cacheDuration: 5m
```

`groups`-based RBAC is enforced by a separate authorization policy over the decoded
claims.

### Snowplow

Snowplow validates the same tokens through the shared `plumbing/jwtutil` (via the
`server/use.UserConfig` middleware), which verifies **RS256 with a public key**
instead of a shared secret. It gets that key from **this endpoint** — there is no
public-key Secret and no key material mounted into Snowplow at all:

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--jwks-url` | `JWT_JWKS_URL` | `""` → `<URL_AUTHN>/.well-known/jwks.json` | Where the key set is fetched from. |
| `--jwks-cache-ttl` | `JWT_JWKS_CACHE_TTL` | `5m` | How long a fetched key set is served before refresh. |
| `--jwks-min-refresh-interval` | `JWT_JWKS_MIN_REFRESH_INTERVAL` | `30s` | Floor between fetch attempts; throttles the refetch an unknown `kid` triggers. |
| `--jwks-request-timeout` | `JWT_JWKS_REQUEST_TIMEOUT` | `5s` | Per-fetch timeout. |

Nothing to distribute: point Snowplow at authn (it already is, via `URL_AUTHN`) and
rotation follows automatically. The mechanics, implemented once in
`plumbing/jwtutil.JWKSKeySource` and reusable by any validator:

- **Lazy fetch.** The key set is fetched on the first token validation, *not* at
  startup — so a validator does not depend on authn being up first and does not crash
  loop while authn restarts.
- **Cached.** Within the TTL, validation is pure local RSA verification; authn is off
  the per-request path.
- **Rotation-aware.** A token whose `kid` is not in the cache triggers a refetch
  (rate-limited by the refresh floor, so an unknown `kid` cannot become a fetch per
  request), which is what lets you rotate the keypair without redeploying validators.
- **Fail-soft.** If a refetch fails but the cache still holds the requested `kid`, the
  stale-but-known key is served: a brief authn outage does not invalidate tokens that
  were already verifiable.
- **Correct status codes.** A key the source couldn't check yields `503` (ours to fix,
  retryable), never `401`: a `401` would tell a browser to discard a good session
  because authn happened to be restarting. That covers an unreachable or empty JWKS, a
  failed latest fetch, a token without `iat`, and a token issued after the cached set
  (a new key at the rotation moment, while the refresh floor blocks a refetch).
- **A retired key is `401`.** From plumbing v1.36.0, a token whose `kid` is missing
  from a key set fetched successfully *after* the token was issued (5s leeway) is
  `ErrTokenInvalid` and `ErrKeyNotPublished`: authn publishes a key from the moment it
  signs with it, so that key was retired. snowplow answers it, from 1.12.69, with `401`
  and the cause `KeyNotPublished`, and the portal asks the user to sign in again.
  Earlier snowplow versions answer `503`.

#### Rotating the signing key

Publish both keys in the JWKS across a rotation (old + new `kid`) so tokens signed
before the switch stay verifiable until they expire. authn signs only with the current
key (`jwt.signKeySecretName`, `jwt.kid`) and publishes every `jwt.previousKeys` entry
for verification only (`JWT_PREVIOUS_KEYS`):

1. Create a Secret with the new private key.
2. In one upgrade, move the current key into `jwt.previousKeys` and point
   `jwt.signKeySecretName` / `jwt.kid` at the new key:
   ```yaml
   jwt:
     signKeySecretName: authn-jwt-signing-key-2
     kid: krateo-authn-key-2
     previousKeys:
       - kid: krateo-authn-key-1
         secretName: authn-jwt-signing-key   # the old key; a public-only PEM also works
         secretKey: private.pem              # default
   ```
   New tokens carry `krateo-authn-key-2`. Validators refetch the JWKS on that unknown
   `kid` and accept them immediately. Tokens signed with `krateo-authn-key-1` keep
   verifying, because that key is still published.
3. After the longest token lifetime has passed (`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`, 24h
   by default), remove the entry, then delete the old Secret.

**The key must survive every upgrade.** authn's chart does not create the signing-key
Secret: the installer's chart does, reusing the existing key through `lookup` and
generating one (`genPrivateKey`) only when `lookup` finds none. `helm template` never
resolves `lookup`, so offline renders always show the generate branch. Only a live check
proves the key was kept. A change in the `/.well-known/jwks.json` body with no rotation
configured (same `kid`, no `previousKeys`) means the key was regenerated, and every
outstanding token stopped verifying. Treat it as an incident, not a roll artefact.

Run each step's upgrade with `--wait` (or follow it with `kubectl rollout status`). A bad
previous-key setting makes the new pod exit at boot while the old pod keeps serving, so
without waiting `helm upgrade` reports success and the rotation silently stalls.

Remove a previous key only after every token it signed has expired. Validators built on
`JWKSKeySource` look the key up before checking expiry. From snowplow 1.12.69, a token
whose `kid` is no longer published is refused with `401` `KeyNotPublished` once
snowplow's cached key set (TTL 5m) is refreshed, and the client signs in again. With
earlier snowplow versions it fails as "key unavailable" (`503`), so a client still
holding one is told to retry, not to sign in again.

#### Revoking tokens

authn has no per-token revocation: the signing key is the only lever. To revoke every
token a key signed, rotate **without** keeping the old key in `jwt.previousKeys`, so
the old `kid` is no longer published. The installer chart's `authn.jwt.keyGeneration`
(installer#782) generates a new key and `kid` for this; check its docs for the roll.
Within the validators' cache TTL (5m for snowplow) the old key stops verifying.
- With snowplow ≥ 1.12.69 and portal ≥ 1.8.36, every signed-in user is asked to sign in
  again ("Sign-in revoked").
- Composition controllers and core-provider cache their authn token until it expires
  and don't re-exchange it on `401` before core-provider#425 ships. Restart them after
  the roll: the cdc Deployments are selected by their `-group=composition.krateo.io`
  argument, not by label.

authn refuses to start when a previous key is unusable: an empty or duplicate `kid`,
the current `kid`, an unreadable or non-RSA file, or the current key under another
`kid`. A retired key that will never verify anything is a misconfiguration, not
something to skip silently. authn's own JWT, used for RESTAction calls, is minted at
startup with the current key, so the upgrade's restart moves it to the new key too.

### The `serviceaccount` strategy

The `/serviceaccount/login` route (Kubernetes intra-service auth) mints its JWT the
same way as every other login strategy — through `encode.Success` with the shared
`JwtPrivateKey`/`JwtKeyID` — so it needs no separate key configuration.

## Migration notes (HS256 → RS256)

- The old shared secret (`JWT_SIGN_KEY` / `AUTHN_JWT_SECRET`) is gone. Replace the
  `authn-jwt-signing-key` Secret's contents with the PEM private key described above.
- **Version alignment:** authn, Snowplow, and any other validator must all build
  against the `plumbing` version that carries the asymmetric `jwtutil`/`UserConfig`
  API. A validator still on the HS256 build will reject the new RS256 tokens.
- Snowplow's `--jwt-sign-key` / `JWT_SIGN_KEY` is gone. It needs no key configuration
  at all now: it reads the public key from this endpoint, derived from `URL_AUTHN`
  unless `JWT_JWKS_URL` overrides it. Any `authn-jwt-public-key` Secret left over from
  an earlier step of this migration is unused and can be deleted.
