---
type: Decision
title: Carrying the requesting human through agent delegation (AUDIT-6)
description: Proposal — authn issues a delegated JWT that names both the acting agent and the human it acts for, via RFC 8693 token exchange, so snowplow's AuditEvent can record on_behalf_of from a verified token instead of client-set baggage.
resource: serviceaccounts.serviceaccount.authn.krateo.io
status: implemented
tags: [decision, audit, delegation, jwt, token-exchange]
timestamp: 2026-11-08T00:00:00Z
---

# Design: carrying the requesting human through agent delegation (AUDIT-6)

> Status: **implemented** in `internal/routes/delegate` (`POST /delegate`), to ship in
> 0.37.0. Accepted by Diego on 2026-11-08. The `act` claim lives in
> `plumbing/jwtutil` since v1.30.0, so snowplow validates it with the same library.
> Implementation deltas from the letter of this design:
> - the form takes RFC 8693's `grant_type` and `subject_token_type` too, and refuses
>   any other value (`400 UnsupportedGrantType`, `UnsupportedSubjectToken`);
> - the answer is RFC 8693's response, `{access_token, issued_token_type,
>   token_type, expires_in}`, sent with `Cache-Control: no-store`.
>
> It answers
> [installer#412](https://github.com/krateo-platformops/installer/issues/412) (AUDIT-6):
> authn defines the identity and issues it, and snowplow writes it into its server-side
> AuditEvent. Diego's decisions are recorded in §4.

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

- **Apiserver audit** (Diego, 2026-11-08: not in step one). The token is a JWT for Krateo's own APIs. A write that reaches
  the apiserver through the human's `<user>-clientconfig` still shows the human there,
  not the agent. Carrying the actor into the apiserver's audit log, for example through
  impersonation extras, is a separate step.
- **Queued work.** A delegated token expires within 15 minutes. A tool that queues work
  has to exchange again when the work runs, or record the chain at enqueue time. That's
  the tool's design, and it needs this contract first.

snowplow's AuditEvent is the authoritative trail. Field names there follow the shared
audit vocabulary (installer#716), so `user`, `on_behalf_of` and `delegation` in §2.4 are
meanings, not final names.

## 4. Decisions

Diego decided all four on 2026-11-08:

1. **Claim shape: RFC 8693 `act`.** `sub` is the human, `act.sub` is the agent, and a
   chain nests.
2. **Authorization: the human's groups,** as under `TOKEN_PASSTHROUGH`, minus reserved
   `krateo:loa:` groups. Only the audit gains the agent.
3. **Opt-in and limits: per-mapping.** An agent may delegate only if its
   `ServiceAccount` mapping sets `spec.delegation.allowed: true`. `maxDepth` defaults
   to 3 and the token lifetime is 15m.
4. **Unverified hops: flag it, with the hint.** snowplow records the agent as `user`,
   no `on_behalf_of`, `delegation_verified: false`, and the baggage value as a labelled,
   unverified hint.

### 4.1 An identity provider's access token as the subject (authn#155)

For IDE sign-in to Agentiko over MCP, Diego decided on 2026-11-13:

1. **Keycloak is the OAuth authorization server.** The IDE signs the person in to the
   same realm as the portal and refreshes its own tokens; authn grows no
   `/authorize`, `/token` or refresh tokens.
2. **authn exchanges the access token** at `/delegate` (`subject_token_type`
   `urn:ietf:params:oauth:token-type:access_token`), so every internal hop keeps one
   issuer and each exchange is an audit record. The actor is the bridge's mapping.
3. **Claim-first:** the person's username must already carry exactly their claim from a
   portal sign-in. An exchange writes no session Secret, so it never claims a name; otherwise two
   identities could each be exchanged as the same unclaimed name.
4. **Configuration on the actor's mapping:** `spec.delegation.subjectTokens` (the
   OIDCConfigs and the access token's accepted audiences) and `spec.delegation.audiences`
   (what the issued token's `aud` may be).

The access token is verified against the provider's JWKS (RS256 with a `kid`, `iss` exactly,
`iat`, `exp`, `aud`) and must be an access token (`typ: at+jwt` in its header, or
Keycloak's `typ: Bearer` claim), so an ID token the same realm signed can't be
exchanged. It must also carry its user session (`sid`): a service account's
client-credentials token has none, names no person, and is refused as `403
SubjectNotAPerson` (authn#165). An OIDCConfig with `restActionRef` is refused: the exchange would map the
person differently from the sign-in that ran the RESTAction (Diego, 2026-11-13). `/oidc/login`'s ID token, by contrast,
comes back-channel from the token endpoint and needs no signature check. The issued token never outlives the access token,
so with Keycloak's short access tokens the bridge re-exchanges every few minutes.

### 4.2 Each delegated token is issued with its credential (authn#167)

Diego decided on 2026-11-21. snowplow authorizes a delegated token by its username and
groups, then calls the apiserver with the person's `<user>-clientconfig` certificate.
That certificate carries the groups of the last portal sign-in (the ID token, after the
OIDCConfig's RESTAction), while the token carries the access token's groups at exchange
time, so the two checks could disagree. It also lives 24h, renewed only by a sign-in, so
an agent acting for someone who hadn't opened the portal for a day got `401
SessionCredentialMissing`.

1. **authn mints per exchange.** `/delegate` issues, with each token, a certificate for
   exactly its username and groups, for its lifetime (at least the CSR API's 10 minutes).
   The token is clamped to the certificate's granted expiry.
2. **One Secret per person and actor** (changed by §4.3: and set of groups). It is named
   by plumbing's `endpoints.DelegatedSecretName`, replaced by each exchange through that
   actor, and deleted by the sweep once expired. Two actors never replace each other's.
3. **snowplow reads it for any token with `act`,** and serves it only when
   `endpoints.CheckDelegatedCredential` finds it held. Otherwise it answers `401`
   `DelegatedCredentialMissing` or `DelegatedCredentialMismatch`, and the client
   exchanges again (snowplow#1560).

Rejected:
- snowplow impersonating the token's identity: it needs an any-user, any-group
  `impersonate` grant;
- renewing `<user>-clientconfig` on `/delegate`: it fixes the lifetime only, and the
  portal's certificate would flip groups;
- one Secret per person: two agents would knock out each other's;
- one per token: Secret and CSR churn.

The apiserver's own audit still shows the person, not the agent (§3).

### 4.3 Tokens for one recipient, and a gateway that exchanges

Diego decided on 2026-11-24, for tool servers that act for a person: each receives a token
only it accepts, and reaches Kubernetes with the person's certificate.

1. **The gateway's own token exchange swaps the token** (RFC 8693), rather than a service
   of ours. agentgateway can sign a client assertion (RFC 7523) and can't send its
   ServiceAccount token, so `/delegate/token` accepts one for a mapping that registers a
   key (`spec.clientAssertion`). Proven on agentgateway v1.5.0 and v1.7.0: the tool server
   gets only a token for its audience, the apiserver sees the person, and a failed
   exchange sends nothing on.
2. **On the internal listener only, over TLS.** A person's token and the assertion travel
   in the request. `/delegate` keeps taking only a ServiceAccount token.
3. **The key is a Secret's certificate**, read on every exchange: cert-manager rotates it
   with no restart. A service's ServiceAccount stays its identity for everything else.
4. **An audience is checked by the recipient** (`jwtutil.WithAudience`,
   `WithRequiredAudience`): a token naming someone else is refused, one naming no one is a
   sign-in's. At the exchange, `audienceRequired` and `subjectAudiences` keep a limited
   token from being widened.
   An audience is the target's in-cluster Service name and namespace,
   `<service>.<namespace>`: `snowplow.krateo-system` for snowplow, `kagent-tools.<namespace>`
   for a tool server. There is one per target and none is shared, so a token for one
   target is refused by every other recipient that checks its audience. A recipient reads its own name from configuration,
   not from code. We do not use https URIs: there is no external issuer to tell apart, and
   the short form reads well in audit records.
   **A gateway that fronts several targets** (Diego, 2026-11-28, for the Agentiko bridge and
   `krateo-agent-gateway`). The first actor, the bridge, exchanges the person's token for one
   whose audience is the gateway's own name, `krateo-agent-gateway.krateo-system`: the gateway
   receives it and forwards it along a path, through an agent, to many tools. The gateway then
   exchanges it per target at `POST /delegate/token` for a token whose audience is that
   target's own name. The mappings:
   - the first actor: `spec.delegation.audiences` lists the gateway's name (and any other
     target it calls directly, such as `snowplow.krateo-system`), `audienceRequired: true`,
     `maxDepth: 1`;
   - the gateway: `subjectAudiences: [<its own name>]`, so authn accepts a subject token
     addressed to it (`verifySubject` checks it with `WithAudience(subjectAudiences...)`; a
     token with no `aud` is accepted anyway), `maxDepth: 2`, because the new `act` is
     `{sub: gateway, act: <the subject's act>}` and the chain counts the new link,
     `audiences` listing each target, and `audienceRequired: true`.

   The person's `principal` is kept from the subject token. Each actor gets its own delegated
   credential, keyed on the outermost actor (`endpoints.DelegatedSecretName(username, actor,
   groups)`); two exchanges by the same actor for the same person and groups share one Secret,
   replaced each time, which is harmless because `endpoints.CheckDelegatedCredential` compares
   username, actor, groups and validity, not the token. A token never outlives its subject
   token. Three rules go with the pattern:
   - A hop that only forwards the token, the agent, is not a recipient: if it ever checks
     `aud`, it accepts the gateway's name, not its own.
   - A target starts checking its own audience (`WithAudience(<its name>)`) only after the
     gateway exchanges for its route. Until then the route forwards a token addressed to the
     gateway, and a target that checks would refuse every call.
   - A token addressed to the gateway is never sent to a target directly (snowplow, say):
     the first actor makes a separate exchange naming that target.
5. **One delegated credential per person, actor and set of groups**, changing §4.2's one
   per person and actor. A client that caches a token, as a gateway does, kept presenting
   it after another sign-in of the person with other groups had replaced the Secret, and
   was refused until it expired (5 of 6 calls, measured). No delegated credential was in
   use, so nothing was migrated; the reader moves with the writer.

A replica takes an assertion once; another replica would take it again within its five
minutes. Replaying one needs the gateway's TLS connection to authn. A shared store for
`jti` was left out: it would put a write in front of every exchange.

Rejected:
- a small exchange service of ours beside the gateway: the gateway already has one;
- a client secret (`client_secret_basic`): a shared secret to distribute and rotate;
- one audience for all tool servers: a compromised one could use its token at another.
- for a gateway chain, the agent's name as the audience: it couples every tool route to one
  agent's name;
- for a gateway chain, no audience: it leaves a token every recipient accepts and
  contradicts `audienceRequired`.
