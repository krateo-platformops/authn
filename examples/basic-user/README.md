---
type: Example
title: basic-user — a User CR enabling the basic login strategy
description: A password Secret + User CR that make the basic strategy appear in /strategies; one curl logs in and returns a kubeconfig + JWT.
resource: users.basic.authn.krateo.io
tags: [basic, user, login]
timestamp: 2026-08-07T00:00:00Z
---

# basic-user

The smallest useful authn setup: a password Secret plus a `User` CR. As soon as one
`User` exists, `GET /strategies` starts advertising the `basic` strategy, and the
user can log in with HTTP Basic auth.

## Preconditions

- authn deployed with its CRDs — a stock Krateo installer deploy (authn in
  `krateo-system`), or the direct install in [usage](../../docs/usage.md).
- The manifest targets `krateo-system`: the `User` CR (and its Secret) **must live in
  authn's operator namespace** — CRs in any other namespace are invisible to authn
  ([gotchas](../../docs/gotchas.md)). If your release namespace differs, edit the
  manifest accordingly.

## Apply

```sh
kubectl apply -f ./manifest.yaml
```

## Log in

`AUTHN_HOST` is the authn Service endpoint (in-cluster
`authn.krateo-system.svc.cluster.local`, or however you exposed it):

```sh
# The strategy is now listed:
curl -s "http://${AUTHN_HOST}:8082/strategies"

# Basic login — username cyberjoker, password 123456:
curl -s -u cyberjoker:123456 "http://${AUTHN_HOST}:8082/basic/login"
```

The response is the standard login contract ([api](../../docs/api.md)):
`accessToken` (a JWT), `user`, `groups: ["devs"]`, and `data` — a ready-to-use
kubeconfig whose client certificate carries `CN=cyberjoker, O=devs`. What that
identity can *do* is whatever RBAC you bind to the `devs` group; authn only
authenticates. Append `?d` to download the kubeconfig as a file.
