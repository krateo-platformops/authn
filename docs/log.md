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
