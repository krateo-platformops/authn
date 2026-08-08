---
type: Guide
title: authn — RBAC: binding Kubernetes roles to certificate users and groups
description: How a login's generated client certificate carries the identity (CN=username, O=groups) and how standard Kubernetes RBAC — RoleBinding/ClusterRoleBinding with User and Group subjects — authorizes it. authn issues identity; it never authors RBAC.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [authn, rbac, authorization, certificates, security]
timestamp: 2026-08-08T00:00:00Z
---

# RBAC: binding roles to certificate users and groups

authn does **authentication**, not **authorization**. Every successful login mints a
short-lived **client-certificate kubeconfig** whose certificate *is* the identity; what
that identity is allowed to do is decided entirely by ordinary Kubernetes **RBAC** that
**you** (or a Krateo blueprint) bind to it. authn never creates a `Role`, `ClusterRole`,
`RoleBinding` or `ClusterRoleBinding` — see [behavior](./behavior.md) (`spec.groups[]`
"become the issued cert's `O=` … authn never authors RBAC").

This guide traces the bridge between the two: how the certificate encodes the user and
their groups, how the Kubernetes apiserver reads them, and how to bind roles so those
subjects gain permissions.

## 1. What the generated certificate carries

On login, authn generates a private key + an X.509 **certificate signing request** whose
subject encodes the caller's identity:

- **`CommonName` (CN) = the username**;
- **`Organization` (O) = the groups** — one `O` entry per group; nothing is injected or
  defaulted (authn adds no cluster-side default group).

Code-traced (paths under `go/authn/`):

- `internal/helpers/kube/certs.go:38-45` — `NewCertificateRequest` sets
  `pkix.Name{CommonName: username, Organization: groups}`.
- `internal/helpers/kube/config/gen.go:24-36` — `generateClientCertAndKey` passes the
  resolved `username`/`groups` straight into that request.

**Where the username and groups come from is strategy-specific** — but whatever the
source, they land in the cert's CN and O the same way:

| Strategy | Username (→ CN) | Groups (→ O) |
|---|---|---|
| `basic` | the `User` CR's `metadata.name` | the `User`'s `spec.groups[]` |
| `serviceaccount` | the mapping CR's `metadata.name` | the mapping's `spec.groups[]` |
| `oidc` | the `preferred_username` claim (DNS-1123-normalized) | the `groups` claim |
| `oauth` | the `preferred_username` field (DNS-1123-normalized) | the `groups` field |
| `ldap` | the entry's `uid` attribute | the entry's `ou` attribute values |

(`basic/login.go:131`, `oidc/login.go:161`, `oauth/login.go:176`,
`ldap/support.go:148-150`, and the serviceaccount mapping; see [behavior](./behavior.md)
for the per-strategy detail.) The RBAC below is identical regardless of strategy — it
binds to the resulting **username** and **groups**.

authn wraps the request in a Kubernetes `CertificateSigningRequest` with signer
**`kubernetes.io/kube-apiserver-client`**, creates it, **self-approves** it, and waits for
the cluster's signer (kube-controller-manager, using the cluster CA) to issue the cert
(`certs.go:160-177`, `config/gen.go:36-84`). Because the cert is signed by the cluster CA
under the kube-apiserver-client signer, the apiserver trusts it for client authentication.

> The broad CSR permissions **authn itself** needs to create and approve those requests are
> a separate concern — see [gotchas → "CSR RBAC is mandatory"](./gotchas.md#csr-rbac-is-mandatory--and-broad).
> That RBAC lets authn *mint* certs; the RBAC in this guide governs what the *minted user*
> can then do.

## 2. How Kubernetes turns the certificate into a subject

When the user calls the apiserver with that kubeconfig, the X.509 **client-cert
authenticator** maps the certificate subject onto the request's identity:

| Certificate field | Becomes | RBAC subject `kind` |
|---|---|---|
| `CN` (CommonName) | the **user** name | `User` |
| each `O` (Organization) | a **group** membership | `Group` |

Kubernetes also adds every authenticated caller to the built-in `system:authenticated`
group automatically — so a user with no explicit binding is *authenticated* but
*unauthorized* (`403`) until a Role is bound to their username, one of their groups, or a
group like `system:authenticated`.

## 3. Binding roles to the identity

RBAC has two halves: a **role** (a set of permissions — namespaced `Role` or cluster-wide
`ClusterRole`) and a **binding** (`RoleBinding` for a namespace, `ClusterRoleBinding`
cluster-wide) that grants that role to **subjects**. To authorize an authn identity, make
its user or group a subject.

### Bind to a user (the certificate CN)

Grant one specific person a role. The subject `name` must equal the `User`'s
`metadata.name` (= the CN):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cyberjoker-edit
  namespace: demo-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit                 # a built-in ClusterRole, used namespace-scoped here
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: cyberjoker         # == User metadata.name == certificate CN
```

### Bind to a group (the certificate O)

Bind once to a group and **every** user that lists it in `spec.groups[]` inherits the
permissions — the scalable lever. Given a `User` with `spec.groups: [devs]`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: devs-view
  namespace: demo-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: devs               # == an O= entry from User spec.groups
```

### Cluster-wide

For permissions across all namespaces, use a `ClusterRoleBinding` with the same subject
shapes — e.g. grant an admin user `cluster-admin`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: admin
```

## 4. End-to-end example

Define the identity (authn `User` — see [examples/basic-user](../examples/basic-user/README.md)),
then bind RBAC to it:

```yaml
# 1) identity — basic strategy: on login authn mints a cert with CN=cyberjoker, O=devs
apiVersion: basic.authn.krateo.io/v1alpha1
kind: User
metadata:
  name: cyberjoker
  namespace: krateo-system      # MUST be authn's operator namespace
spec:
  displayName: Cyber Joker
  groups:
    - devs
  passwordRef:
    namespace: krateo-system
    name: cyberjoker-password
    key: password
---
# 2) authorization — bind the "devs" group to a namespaced role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: devs-view
  namespace: demo-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: devs
```

In a full Krateo install this is exactly how the seeded users are wired: the **portal**
component provisions an `admin` user bound to `cluster-admin` and a `cyberjoker` demo user
bound namespace-scoped (toggled by `componentValues.portal.enableAdminUser` /
`enableCyberjokerUser` on the installer) — the RBAC lives outside authn, bound to the
identities authn issues.

## 5. Things worth knowing

- **The subject name is a plain string match.** A `RoleBinding` to user `cyberjoker` matches
  the cert CN `cyberjoker` exactly — a typo, or a rename of the `User` CR, silently drops
  the grant. Groups match the same way against the `O=` entries.
- **Groups are the durable, scalable lever.** Bind a role to a group once; add or remove
  members by editing each `User`'s `spec.groups[]`. No RBAC change is needed to onboard a
  new person into an existing group.
- **RBAC outlives the certificate.** The minted cert is short-lived (its lifetime is the
  configured cert duration) and re-issued on every login, but it always carries the same CN
  and O for a given `User`, so bindings — keyed on the stable user/group *names* — keep
  working across re-logins. You bind once, not per session.
- **No binding ⇒ 403.** Authentication succeeding only means the apiserver knows *who* the
  caller is. Without a Role bound to their user, one of their groups, or a broad group like
  `system:authenticated`, every authorized action is denied.
- **`User` CRs must live in authn's operator namespace** (the release namespace) or they are
  invisible to the resolver — but the **RBAC** objects live wherever the permission applies
  (`RoleBinding` in the target namespace, `ClusterRoleBinding` cluster-wide).

## See also

- [behavior](./behavior.md) — the login/response contract and where each strategy sources
  username/groups (CN/O).
- [api](./api.md) — the five `*.authn.krateo.io` CRDs, including `User.spec.groups`.
- [gotchas](./gotchas.md#csr-rbac-is-mandatory--and-broad) — the CSR RBAC **authn itself**
  needs to mint certs (distinct from this guide).
- [examples/basic-user](../examples/basic-user/README.md) — a `User` + password Secret.
