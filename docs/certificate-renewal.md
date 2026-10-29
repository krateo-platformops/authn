---
type: Architecture
title: authn — client certificate renewal
description: How authn keeps its own client certificate alive with a background renewal loop, why per-user certificates are clamped instead of renewed, and how to verify it per distribution.
tags: [authn, x509, csr, certificate, renewal, jwt]
timestamp: 2026-10-29T00:00:00Z
---

# Client certificate renewal

authn mints x509 client certificates through the Kubernetes CSR API (signer
`kubernetes.io/kube-apiserver-client`) and stores them in `<name>-clientconfig`
Secrets. There are two kinds of identity, and authn keeps them alive in different ways:

| Secret | Whose identity | How it stays valid |
|---|---|---|
| `authn-clientconfig` | authn's own; snowplow presents it when it runs RESTActions for authn | **Renewed** in the background |
| `<user>-clientconfig` | each logged-in user or service | **Clamped**: the login JWT never outlives it, and every login re-mints it |

## The requested duration is not the granted duration

The signer grants `min(requested expirationSeconds, cluster-signing-duration, signer CA
remaining life)`.

- **Vanilla Kubernetes:** `--cluster-signing-duration` defaults to `8760h`, so the year
  authn asks for usually survives. That is why the problem stays invisible until you
  deploy elsewhere.
- **OpenShift:** the signing duration is pinned to 720h and the CSR signer CA rotates
  every 30 days. A certificate requested for a year comes back valid for at most 30 days,
  and for a single day when a rotation is close.

So authn reads `NotAfter` off the issued certificate instead of assuming the request
held. It annotates every stored Secret with the window it was actually granted
(`storage.NotBeforeAnnotation` / `NotAfterAnnotation`,
`go/authn/internal/helpers/kube/config/storage/storage.go:29-30`):

```sh
$ kubectl -n krateo-system get secret authn-clientconfig -o jsonpath='{.metadata.annotations}'
{"authn.krateo.io/certificate-not-before":"2026-09-04T10:00:00Z","authn.krateo.io/certificate-not-after":"2026-10-04T10:00:00Z"}
```

When the granted window is under 90% of the requested one, authn logs a `warn` at
issue time (`kube.MateriallyShorter`, `go/authn/internal/helpers/kube/certinfo.go:57`).
That warning is the only sign that a signer is capping you.

Nothing reads these annotations back; the renewal loop decides from the stored
certificate itself. They exist so an operator can see when every credential in a
namespace really expires without decoding anything:

```sh
kubectl get secret -o custom-columns=NAME:.metadata.name,EXPIRES:'.metadata.annotations.authn\.krateo\.io/certificate-not-after'
```

### Why `NotAfter` can be trusted

- **A certificate never outlives its CA.** Kubernetes' signer sets the issued
  `NotAfter` to `min(now + ttl, signer CA NotAfter)`
  (`pkg/controller/certificates/authority/policies.go`) and refuses to sign once the
  CA itself has expired.
- **Signings after a rotation use the new CA.** The signer hot-reloads its CA from disk.
- **Rotation keeps old certificates trusted.** On OpenShift, library-go's
  `manageCABundleConfigMap` prepends the new signer to the CA bundle and prunes only
  certificates that have actually expired. A certificate issued by a rotated-out CA
  stays trusted up to its own `NotAfter`.

So renewing at a fraction of the granted window is always in time.

A CA being *rotated* in five days is not the same as it *expiring* in five days. If the
old CA certificate is still valid for 25 more days, you are granted up to those 25 days,
and that is correct, because the rotated-out CA stays in the bundle until it expires.

**What this cannot see:** a signer CA regenerated out of band, with its trust bundle
rebuilt from scratch (disaster recovery, a manual signer wipe). Certificates issued
before that stop being accepted while their `NotAfter` is still in the future. This
shows up as `x509: certificate signed by unknown authority`, not as an expiry. authn
cannot detect it, because snowplow presents the certificate, not authn. To recover,
restart the pod or `kubectl delete secret authn-clientconfig`.

## `authn-clientconfig` is renewed in the background

Before this, nothing but a pod restart re-issued authn's own certificate. Unlike a
user's certificate, no login rewrites it. A pod that outlived its certificate failed
every RESTAction call with `x509: certificate has expired or is not yet valid`.

`go/authn/internal/certrenewal` (wired in `go/authn/main.go`) issues the certificate at
startup. It re-issues it once the certificate passes `AUTHN_CRT_RENEWAL_THRESHOLD` of
its **granted** lifetime. Because the threshold is a fraction of what was granted, not
of what was requested, one setting covers both cases:

- a full year is re-issued after about 8 months;
- a certificate cut to an hour by a rotating signer CA is re-issued after about 40 minutes.

The loop does not poll. The signing call returns the certificate, and the clamp above
makes its `NotAfter` deterministic, so the loop sleeps straight to the due time.

| Env var | Flag | Default | Effect |
|---|---|---|---|
| `AUTHN_SERVICE_CRT_EXPIRES_IN` | `--service-cert-expires` | `8760h` | Requested lifetime of authn's own certificate. |
| `AUTHN_CRT_RENEWAL_THRESHOLD` | `--cert-renewal-threshold` | `0.66` | Fraction of the granted lifetime after which it is re-issued. Must be strictly between 0 and 1; an out-of-range value falls back to the default (the chart schema rejects it). |
| `AUTHN_CRT_RENEWAL_ENABLED` | `--cert-renewal` | `true` | `false` restores the old behaviour: the certificate expires in place until the pod restarts. |

All three are under `env` in the chart values.

**Failures:**
- A failed issue retries after a minute.
- A failed read never triggers a re-issue: an apiserver hiccup is not evidence that the
  credential is gone.

**Out-of-band changes:** since nothing polls, a Secret deleted or replaced out of band
is noticed only at the next scheduled re-issue. Deleting it still forces a fresh
certificate, but it takes effect immediately only after a pod restart.

**RBAC:** none added. The annotations are written with the `get` and `update` on
`secrets` that authn already holds.

**Single writer:** the loop assumes one writer. The CSR object is named after the
username, so two replicas would race on the CSR named `authn`. Keep `replicaCount: 1`
and `autoscaling.enabled: false`, which are the chart defaults
([gotchas](./gotchas.md)).

## `<user>-clientconfig` is clamped, not renewed

Per-user certificates are deliberately left off the renewal loop. Instead, the login JWT
is issued for `min(AUTHN_KUBECONFIG_CRT_EXPIRES_IN, time until the certificate's real
NotAfter)` (`tokenDuration`, `go/authn/internal/helpers/encode/success.go:37`). Every
strategy does this, including `serviceaccount`.

**The bug this closes:** the JWT lifetime used to come from the requested duration. A
signer-truncated certificate left the user logged in while every user-scoped call
failed with an x509 error, and with no refresh endpoint the only recovery was waiting
out the JWT. With the clamp, the certificate outlives every token issued against it. A
user certificate is also re-minted on every login, so there is no gap left for a
background loop to cover.

**Renewing them would make things worse:**
- it would rewrite the Secret, but not the copy of the kubeconfig the caller already holds;
- it would keep minting valid cluster credentials for identities long since
  deprovisioned upstream. authn cannot check that, because it learns who someone is at
  login and holds no session state.

## Verifying it

Certificate handling differs per distribution, so it has to be measured, not reasoned
about. [`go/authn/scripts/verify-cert-renewal.sh`](../go/authn/scripts/verify-cert-renewal.sh)
reports the granted `NotAfter`, checks that renewal fires before expiry, and proves the
renewed certificate still authenticates against the apiserver:

- `--wait` forces a renewal now, by collapsing the threshold and restarting authn;
- `--short 15m` reinstalls authn with a lifetime short enough to watch a full cycle in about 10 minutes.

Run it on each flavour you support (kind, minikube, k3s/k3d, EKS, AKS, GKE, OpenShift)
and record the row it prints.

**Verified so far:**
- **kind:** 7 consecutive renewals at a 10m TTL, each firing about 9 minutes before its
  own expiry, and each renewed certificate accepted by the apiserver.
- **Capped signers:** kind honours `spec.expirationSeconds` in full, so a capped signer
  is still unexercised. The other flavours are tracked in
  [authn#28](https://github.com/krateo-platformops/authn/issues/28).
