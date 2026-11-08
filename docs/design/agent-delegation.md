---
type: Decision
title: Carrying the requesting human through agent delegation (AUDIT-6)
description: Proposal — authn issues a delegated JWT that names both the acting agent and the human it acts for, via RFC 8693 token exchange, so snowplow's AuditEvent can record on_behalf_of from a verified token instead of client-set baggage.
resource: serviceaccounts.serviceaccount.authn.krateo.io
status: proposed
tags: [decision, audit, delegation, jwt, token-exchange]
timestamp: 2026-11-08T00:00:00Z
---

# Design: carrying the requesting human through agent delegation (AUDIT-6)

> Status: **proposed**. Nothing here is implemented. It answers
> [installer#412](https://github.com/krateo-platformops/installer/issues/412) (AUDIT-6):
> authn defines the identity and issues it, and snowplow writes it into its server-side
> AuditEvent. The decisions marked **Decision** need Diego's choice before any code.

## 1. The problem

When a user asks an agent to do something, the platform performs the action as the
agent. With `TOKEN_PASSTHROUGH`, the agent replays the user's JWT, so the authorization
is right. But the audit record names whichever credential was presented, and that's not
predictable:

- an agent step that uses its own identity (`/serviceaccount/login`) records the agent
  and loses the human;
- an agent step that replays the user's JWT records the human and loses the agent;
- work queued for later keeps neither.

So the human isn't reliably recoverable, and nor is the agent. Neither credential says
"agent X acting for user Y".

Baggage (`session.id` today) could carry a human's name across hops, but a caller can set
baggage to anything. It can carry a correlation id. It can't carry identity
([installer#398](https://github.com/krateo-platformops/installer/issues/398), OTEL-6).

## 2. Proposal: a delegated token, issued by authn

authn already holds both halves of the proof. It signs every user's JWT, and it can
authenticate an agent's ServiceAccount token through TokenReview and the `ServiceAccount`
mapping allowlist (`/serviceaccount/login`). A new route exchanges the two for one
token that names both.

### 2.1 The exchange: `POST /delegate`

The route follows OAuth 2.0 Token Exchange
([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) in shape:

| Input | Carries | authn verifies |
|---|---|---|
| `Authorization: Bearer <projected SA token, audience authn>` | the **actor**: the agent's own identity | TokenReview, then exactly one `ServiceAccount` mapping, exactly as `/serviceaccount/login` (§4 of the [intra-service design](./kubernetes-intra-service-auth.md)). The mapping must also allow delegation (§2.3) |
| `subject_token=<authn JWT>` (form body) | the **subject**: the human, or an earlier delegated token | authn's own signature against its JWKS keys (current and previous), and `exp` |

authn answers with a new JWT (§2.2) and no kubeconfig. Failures follow the
[failure contract](../api.md#what-a-caller-should-do-with-a-failure), with new causes
such as `SubjectTokenInvalid` (401), `DelegationNotAllowed` (403) and
`DelegationTooDeep` (403).

### 2.2 The delegated token

The token uses the same RS256 key and `kid`, and the same claims as today: `username`,
`groups`, `iss`, `sub`, `exp`, `iat` and `nbf`. It adds RFC 8693's `act` claim:

```json
{
  "iss": "krateo.io",
  "sub": "alice",
  "username": "alice",
  "groups": ["devs"],
  "act": { "sub": "krateo-kagent-dashboard" },
  "exp": 1762600000
}
```

- **`sub` and `username` stay the human's**, so every existing validator (snowplow,
  agentgateway) keeps authorizing as it does under `TOKEN_PASSTHROUGH`.
- **`act.sub` is the agent's username**: the `ServiceAccount` mapping's name, the same
  identity `/serviceaccount/login` issues.
- **A chain nests.** When an agent exchanges a delegated token again, authn wraps the
  existing `act` inside the new one: `{"sub": "agent-b", "act": {"sub": "agent-a"}}`.
  The outermost `act.sub` is always the current actor (RFC 8693 §4.1).
- **`exp` is the earlier of** the subject token's `exp` and a short delegation TTL
  (default 15m). A delegated token never outlives the human's session.
- **Reserved groups are dropped.** A `krateo:loa:` step-up group never passes through
  delegation, because an agent didn't prove a fresh, stronger sign-in.

### 2.3 Who may delegate

Being able to log in as a service isn't enough. A new optional field on the
`ServiceAccount` mapping, `spec.delegation.allowed: true`, opts an agent in. Without
it, `/delegate` refuses with 403 `DelegationNotAllowed`. `spec.delegation.maxDepth`,
default 3, caps the chain.

### 2.4 What snowplow records

snowplow derives the audit fields only from the verified JWT, never from baggage:

| AuditEvent field | Source |
|---|---|
| `user` | the outermost `act.sub` when `act` is present, otherwise `username` |
| `on_behalf_of` | `sub` when `act` is present; absent otherwise (the human acted directly) |
| `delegation` | the `act` chain, outermost first, ending at `sub` |

Some calls can't show a verified human, such as an agent using its own token while
baggage names someone. snowplow records the agent as `user`, omits `on_behalf_of`, and
sets `delegation_verified: false` with the baggage value as an unverified hint. That
meets #412's "a hop that cannot establish the human records that fact explicitly".

## 3. Out of scope for the first step

- **Apiserver audit.** The token is a JWT for Krateo's own APIs. A write that reaches
  the apiserver through the human's `<user>-clientconfig` still shows the human there,
  not the agent. Carrying the actor into the apiserver's audit log, for example through
  impersonation extras, is a separate step.
- **Queued work.** A delegated token expires within 15 minutes. A tool that queues work
  has to exchange again when the work runs, or record the chain at enqueue time. That's
  the tool's design, and it needs this contract first.

## 4. Decisions for Diego

1. **Claim shape.** RFC 8693 `act` (recommended: standard, chains naturally, and other
   validators already understand it), or a custom `on_behalf_of` claim.
2. **Authorization of the delegated token.** The human's groups, as `TOKEN_PASSTHROUGH`
   does today (recommended for step one: no behaviour change), or the intersection of
   the human's and the agent's groups (stricter, and agents' groups would need defining).
3. **Opt-in and limits.** `spec.delegation.allowed` on the mapping, with a 15m TTL and
   depth 3 by default.
4. **Unverified hops.** snowplow records `delegation_verified: false` plus the baggage
   hint, or records nothing about the human at all.
