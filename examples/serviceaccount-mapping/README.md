---
type: Example
title: serviceaccount-mapping — intra-service auth allowlist
description: A ServiceAccount mapping CR that lets a backend service exchange its own projected, audience-bound SA token for a Krateo JWT + kubeconfig via POST /serviceaccount/login.
resource: serviceaccounts.serviceaccount.authn.krateo.io
tags: [serviceaccount, tokenreview, intra-service-auth]
timestamp: 2026-08-07T00:00:00Z
---

# serviceaccount-mapping

Kubernetes **intra-service auth**: a backend service authenticates to authn with its
*own* ServiceAccount token — no password, no browser redirect — and receives the same
JWT + kubeconfig human users get. The `ServiceAccount` mapping CR is the **exchange
allowlist**: no mapping, no exchange
([decision record](../../docs/design/kubernetes-intra-service-auth.md)).

## Preconditions

- authn ≥ 0.23.0 deployed with its CRDs — a stock Krateo installer deploy (authn in
  `krateo-system`). The chart already grants authn the required
  `tokenreviews:create` RBAC.
- A Kubernetes ServiceAccount `my-backend-service` in `krateo-system` (edit the
  manifest's `serviceAccountRef` to match your caller):
  `kubectl create serviceaccount my-backend-service -n krateo-system`
- The mapping CR **must live in authn's operator namespace** (`krateo-system` on a
  stock deploy) — mappings elsewhere are invisible and the exchange is rejected
  ([gotchas](../../docs/gotchas.md)).

## Apply

```sh
kubectl apply -f ./manifest.yaml
```

## Exchange

The caller must present a **projected** token bound to authn's audience (default
`authn`) — a legacy SA Secret or a default-audience token is rejected. In the
caller's pod spec:

```yaml
volumes:
  - name: authn-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: authn
            expirationSeconds: 600
# and in the container:
volumeMounts:
  - name: authn-token
    mountPath: /var/run/secrets/tokens
    readOnly: true
```

Then, from that pod:

```sh
curl -s -X POST "http://authn.krateo-system.svc.cluster.local:8082/serviceaccount/login" \
  -H "Authorization: Bearer $(cat /var/run/secrets/tokens/token)"
```

(For a quick out-of-pod smoke test, mint an equivalent audience-bound token with
`kubectl create token my-backend-service -n krateo-system --audience=authn`.)

The response is the standard login contract ([api](../../docs/api.md)) with
username = the mapping's `metadata.name` (`my-backend-service`) and
groups = `["krateo:services"]` — the minted cert's `O=`. Scope the identity by
binding RBAC to that group with a normal `ClusterRoleBinding`; authn never authors
RBAC.
