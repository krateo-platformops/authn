---
type: Runbook
title: authn — release
description: How a release ships — one plain-semver tag drives the image build and the OCI chart publish; what lands where and what to verify.
resource: oci://ghcr.io/krateo-platformops/charts/authn
tags: [release, ci, oci]
timestamp: 2026-08-07T00:00:00Z
---

# Release

One tag ships everything. This monorepo has a single version line: the app image, the
`authn` chart and the `authn-crds` chart all release at the tag's version.

## The runbook

1. **Merge to `main`** with PR CI green
   ([`release-pullrequest.yaml`](../.github/workflows/release-pullrequest.yaml):
   validate-only multi-arch image build, Go tests + CRD-drift guard, docs lint;
   plus chart lint ([`lint.yaml`](../.github/workflows/lint.yaml)) and security
   scanning).
2. **Tag with plain semver — `X.Y.Z`, no `v` prefix.** All release workflows trigger
   on `[0-9]+.[0-9]+.[0-9]+` only; a `v`-prefixed tag ships **nothing**, silently
   (it has happened here: `v0.25.0` produced no artifacts; `0.26.0` is the release
   that followed).

   ```sh
   git tag 0.26.1 && git push origin 0.26.1
   ```

3. **CI builds and publishes**, no manual steps:
   - [`release-tag.yaml`](../.github/workflows/release-tag.yaml) → the shared
     `component-image-build` workflow (`krateo-platformops/.github`) builds the
     multi-arch (amd64+arm64) image from `go/authn/` →
     `ghcr.io/krateo-platformops/authn:X.Y.Z`.
   - [`release-oci.yaml`](../.github/workflows/release-oci.yaml) (the canonical,
     byte-identical org workflow) discovers every first-class chart under `helm/`,
     substitutes the `Chart.yaml` placeholders (`CHART_VERSION` → the tag;
     `APP_VERSION` → the latest app semver tag, which in this monorepo is the same
     tag), packages, and pushes →
     `oci://ghcr.io/krateo-platformops/charts/authn:X.Y.Z` and
     `oci://ghcr.io/krateo-platformops/charts/authn-crds:X.Y.Z`.

4. **Verify** the artifacts exist and pair up:

   ```sh
   helm show chart oci://ghcr.io/krateo-platformops/charts/authn --version X.Y.Z
   # appVersion in the output must equal X.Y.Z
   ```

5. **Roll it out** by bumping the Krateo installer's authn chart pin (both charts
   move together — the installer pins them at one version), or `helm upgrade` on a
   standalone install ([usage](./usage.md)). Never mutate the running Deployment out
   of band.

## CRD changes

CRDs are generated from the Go types (`make generate` in `go/authn/`), drift-gated in
PR CI (`crd_drift: true` in the shared go-checks), committed under
[`go/authn/crds/`](../go/authn/crds/) and shipped via the copy under
[`helm/authn-crds/templates/`](../helm/authn-crds/templates/) — the old cross-repo
CRD publish job into a separate chart repo is gone with the monorepo fold. If you
change `apis/`, regenerate and update the crds chart templates in the same PR.

## Docs

`docs/llms.txt` pins this bundle to the release tag — update the pin (and
[log](./log.md), when the release is notable) as part of the release PR.
