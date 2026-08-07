---
type: Decision
title: Kubernetes intra-service authentication (SA token → service JWT)
description: Decision record — let any in-cluster Krateo service exchange its own audience-bound ServiceAccount token (TokenReview-validated) for an authn JWT + clientconfig; shipped as the serviceaccount login strategy in 0.23.0.
resource: serviceaccounts.serviceaccount.authn.krateo.io
status: implemented
tags: [decision, serviceaccount, tokenreview, intra-service-auth]
timestamp: 2026-08-07T00:00:00Z
---

# Design: Kubernetes intra-service authentication (SA token → service JWT)

> Status: **implemented** — shipped in 0.23.0 (2026-06-20) as designed. The
> `serviceaccount` strategy (`go/authn/internal/routes/auth/serviceaccount/login.go`),
> the `ServiceAccount` mapping CRD
> (`go/authn/apis/authn/serviceaccount/v1alpha1/types.go`) and the TokenReview +
> allowlist flow all match §2–§4. Implementation deltas from the letter of this
> design:
> - the mapping ref type is the existing `core.ObjectRef` (`{namespace,name}`), not a
>   new `ServiceAccountSelector`;
> - the handler issues the kubeconfig + JWT through the shared
>   `KubeconfigGenerator` (which persists the `AuthInfo`) like every other strategy —
>   `signup.Do` stays boot-only for authn's own identity;
> - the issued-JWT TTL is the standard cert-duration knob
>   (`AUTHN_KUBECONFIG_CRT_EXPIRES_IN`, default 24h), not a separate short
>   service-token TTL;
> - the audience is configurable (`--serviceaccount-audience` /
>   `AUTHN_SERVICEACCOUNT_AUDIENCE`, default `authn`).
> Current behavior contract: [behavior.md](../behavior.md); pitfalls:
> [gotchas.md](../gotchas.md). The multi-cluster question (§6) remains open.
>
> Original: Draft for discussion · Date: 2026-06-20
>
> Goal: let any in-cluster Krateo **service** authenticate to authn with its **own
> Kubernetes ServiceAccount token** and receive an authn-issued **JWT bound to a scoped
> `clientconfig`** — the same identity shape human users get — so it can call
> `UserConfig`-gated services (snowplow `/call`, etc.) **unchanged**. This generalises what
> authn already does for its *own* identity.

---

## 1. Why

Krateo back-end services increasingly need to call other Krateo services that are gated by
authn's per-identity model. The motivating case: **core-provider's composition-dynamic
controller (CDC)** must resolve a `RESTAction` through **snowplow** to populate a
Composition's status (see core-provider `docs/design/composition-status-projection.md`).
But snowplow's `/call` (its `UserConfig` middleware) requires an `Authorization: Bearer`
**JWT signed with the shared signing key**, then loads a per-user `<user>-clientconfig` —
i.e. the JWT *is* how snowplow scopes Kubernetes RBAC per identity. A controller is **not a
user** and has no such JWT.

The two obvious workarounds are both bad:

- **Give the caller the signing key** so it self-mints a JWT — leaks a platform-wide secret
  into every consumer.
- **A bespoke no-auth/own-SA endpoint per callee** (e.g. a snowplow service-mode route) —
  per-service special-casing, and it bypasses the per-identity RBAC scoping that is the
  whole point.

**authn already solved this for itself.** On startup it self-mints a service JWT and
provisions its own scoped identity to call snowplow's RESTActions:

- `jwtutil.CreateToken({ Username: "authn", Groups: ["authn"], SigningKey, Duration: 1y })`
  — `go/authn/main.go:195-203`.
- `signup.Do({ Username: "authn", UserGroups: ["authn"], … })` → provisions
  `authn-clientconfig` — `go/authn/main.go:290-299` ("Create authn clientconfig to call
  snowplow's RESTActions").

It can do this only because **it holds the signing key** and runs the signup machinery.
**Generalising that to other services — without handing them the key — is this proposal.**

---

## 2. What

A new **login strategy**, `serviceaccount` (Kubernetes SA token as the credential), slotting
into authn's existing strategy pattern (`internal/routes/auth/{basic,oauth,ldap}` →
`routes.Route` with `Pattern()/Method()/Handler()`, given the `KubeconfigGenerator` + signing
key). No new framework — it is "log in with your Kubernetes SA token".

```
POST /serviceaccount/login
Authorization: Bearer <caller's projected SA token, audience: "authn">
→ 200 { accessToken: <authn JWT>, ... }   # same success shape as the other strategies
```

### Flow

1. **Caller** mounts a **projected SA token** (`TokenRequest`, `audience: authn`, short TTL)
   and presents it as the Bearer credential.
2. **authn validates it via the Kubernetes `TokenReview` API** (`authentication.k8s.io`),
   *with the expected audience*. On success it gets the authenticated
   `username = system:serviceaccount:<ns>:<sa>` and the SA's groups.
3. **Authorization / identity mapping (the security-critical step, §4):** authn looks up a
   **mapping policy** — is this SA allowed to exchange, and to which service identity
   (username + groups) does it map? Unmapped SAs are rejected.
4. **Issue:** authn mints the JWT with the **existing** `jwtutil.CreateToken` (mapped
   username/groups, signing key, short duration) and **ensures the scoped `clientconfig`**
   with the **existing** `signup.Do` / `KubeconfigGenerator`. RBAC for that identity is the
   clientconfig's — least privilege, centralized here.
5. **Return** the JWT (same response shape as `basic`/`oauth`). The caller presents it to
   snowplow `/call` (or any `UserConfig`-gated service) **unchanged**.

**New code is small and bounded:** the `serviceaccount` strategy handler + the `TokenReview`
call + the mapping policy. JWT minting (`jwtutil.CreateToken`), clientconfig provisioning
(`signup.Do`), and the kubeconfig generator already exist and are reused verbatim.

---

## 3. Caller side (e.g. the CDC)

- Project an audience-bound SA token via the Deployment's
  `serviceAccountToken` projected volume (`audience: authn`, `expirationSeconds: ~600`).
- A tiny client (candidate home: **`plumbing`**, so every service shares it): read the
  projected token, `POST /serviceaccount/login`, **cache the returned JWT** until shortly
  before its expiry, present it on downstream calls. This mirrors the existing
  `internal/chartinspector` HTTP-client pattern in the CDC.
- For composition status, the CDC then calls snowplow `/call` with the JWT — no signing key,
  no endpoint credentials in the CDC.

---

## 4. Security model

The exchange must be **strictly bounded** — it issues platform identities:

- **Audience-bound tokens.** Require `audience: authn` on the projected token and pass it to
  `TokenReview`; reject tokens minted for any other audience. Prevents replay of tokens
  issued for the kube-apiserver or other services.
- **Bound SA tokens only.** Use `TokenRequest`-projected, short-TTL, audience-scoped tokens
  — never legacy long-lived SA Secrets.
- **Explicit mapping allowlist.** Only SAs named in the mapping policy can exchange, and the
  policy fixes the **identity + groups** they map to (hence their `clientconfig` RBAC). No
  implicit "any SA → some identity". This is where per-service least privilege is set, and
  it replaces "resolve under snowplow's broad SA".
- **Short JWT TTL** on issued service tokens (re-exchange on expiry; the caller caches
  between).
- **No privilege amplification:** the mapped `clientconfig` should grant only what that
  service legitimately needs (e.g. the reads its RESTActions perform), provisioned/audited in
  one place (authn) rather than scattered across callees.

authn's own SA gains one permission: `create` on
`tokenreviews.authentication.k8s.io`.

### Mapping policy — shape

**It is the existing `basic.User` pattern, with the credential swapped from a password to a
SA token.** Every strategy already has its own per-group CRD (`basic.authn.krateo.io` →
`User`, `oauth.authn.krateo.io` → config, …); the `serviceaccount` strategy gets the same:
a **`ServiceAccount` CRD in `serviceaccount.authn.krateo.io`**, structurally identical to
`basic.User` (`apis/authn/basic/v1alpha1/types.go`) except `serviceAccountRef` replaces
`passwordRef`.

```go
// apis/authn/serviceaccount/v1alpha1/types.go — group serviceaccount.authn.krateo.io
type ServiceAccountSpec struct {
    // The k8s SA allowed to exchange its token for this identity — the credential,
    // analogous to basic.User.passwordRef but verified via TokenReview, not a compare.
    ServiceAccountRef *core.ServiceAccountSelector `json:"serviceAccountRef"` // {namespace,name}
    // Groups the service identity belongs to → issued clientconfig cert O= (certs.go:42)
    // → standard Kubernetes RBAC.
    Groups []string `json:"groups,omitempty"`
    // +optional DisplayName, TokenTTL, Audiences
}
// +kubebuilder:resource:scope=Namespaced,categories={krateo,authn,serviceaccount}
// metadata.name == the issued username (exactly like basic.User).
```

```yaml
apiVersion: serviceaccount.authn.krateo.io/v1alpha1
kind: ServiceAccount
metadata: { name: composition-dynamic-controller, namespace: krateo-system }  # name == username
spec:
  serviceAccountRef: { namespace: krateo-system, name: composition-dynamic-controller }
  groups: [ "krateo:services" ]            # → cert O= → k8s RBAC scoping
```

Consequences (all inherited from the existing model):

- **The CR's existence is the allowlist** — no `ServiceAccount` CR ⇒ no exchange; authoring
  them is gated by RBAC on the CRD (cluster admins).
- **RBAC scoping is standard Kubernetes, not authn's job.** authn mints a client cert
  `CN=<name>, O=<groups>` exactly as for users; you bound a service by binding a `ClusterRole`
  to its **group** via a normal `ClusterRoleBinding`. authn never authors RBAC.
- **Zero new concepts** — anyone who knows `basic.User` knows this; the only new field is
  `serviceAccountRef`, and TokenReview replaces the password compare.

---

## 5. Why this is the right layer

- **One mechanism, platform-wide.** Any Krateo service → any `UserConfig`-gated service.
  The composition-status CDC→snowplow path is just the first consumer.
- **No callee changes.** snowplow `/call` and its `UserConfig` are untouched; the service is
  simply a first-class identity with a `clientconfig`.
- **No secret sprawl.** The signing key never leaves authn; callers use k8s-native,
  audience-bound, short-lived SA tokens validated by the apiserver (`TokenReview`).
- **Reuses existing authn machinery** (`jwtutil.CreateToken`, `signup.Do`, kubeconfig
  generator) — already exercised by authn's own identity.

---

## 6. Open questions

- ~~Mapping policy home & shape~~ — **resolved (§4):** a `ServiceAccount` CRD in
  `serviceaccount.authn.krateo.io`, the `basic.User` pattern with `serviceAccountRef`
  instead of `passwordRef`; RBAC stays standard k8s bound to `spec.groups`.
- **Token audience & naming** — the canonical audience string and service-username scheme
  (`svc:<name>`?). _Group convention — **resolved** by the composition-dynamic-controller
  integration: the per-composition group is `krateo:cdc:<resource>-<apiVersion>` (core-provider
  auto-provisions a `ServiceAccount` mapping carrying that group)._
- **JWT lifetime & caching** — issued-token TTL vs. caller cache window; revocation story.
- **Multi-cluster — `TokenReview` is cluster-local** (it validates against the apiserver
  that *issued* the token). A service in a **remote target** cannot be authenticated by
  mgmt-authn directly. Direction (mirrors composition-status, which resolves this by making
  resolution cluster-local): **prefer authn target-local** in the remote case — auth runs
  where the service runs, validating the local token — paired with target-local resolution.
  **Fallback:** extend mgmt-authn to `TokenReview` against a **registered target's
  apiserver** using the client core-provider already holds (the `KubernetesTarget` Secret) —
  reuses existing plumbing but couples authn to the target registry and keeps custody
  central. Local-cluster services (the common case) are unaffected.
- **Endpoint path/verb** — `/serviceaccount/login` (POST) vs. a token-exchange-style
  `/token` (RFC 8693 framing).
- **Bootstrap ordering** — authn must be reachable before dependent controllers can resolve
  `apiRef`; degrade gracefully (status fields stale, never a failed reconcile).

---

## 7. Scope

In: the `serviceaccount` login strategy (TokenReview + mapping + issue), authn SA RBAC for
`tokenreviews`, a shared caller client (plumbing). Out (separate): the consumers
(core-provider/CDC wiring lives in its own design), and the multi-cluster validation path
(tracked with the composition-status multi-cluster question).
