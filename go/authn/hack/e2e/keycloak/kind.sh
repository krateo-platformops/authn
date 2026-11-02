#!/usr/bin/env bash
# The kind harness for the Keycloak step-up e2e: a kind cluster and authn
# built from a git ref; then cluster.sh installs authn with its helm chart,
# Keycloak and the OIDCConfigs in krateo-system and runs realm.sh and stepup.sh.
#
#   go/authn/hack/e2e/keycloak/kind.sh
#
# Env:
#   REF=HEAD                  the authn ref to build (git archive of it: uncommitted changes are not included)
#   CLUSTER=authn-keycloak    the kind cluster; it gets its own kubeconfig file in WORKDIR
#   KEEP=0                    1: keep the cluster afterwards
#   KC_IMAGE=quay.io/keycloak/keycloak:26.4
#   WORKDIR=${TMPDIR:-/tmp}/authn-e2e-keycloak
#   SKIP=                     passed to stepup.sh, e.g. "d e f" for a quick run (f, the
#                             step-up sweep, waits for a real expiry: about 20 minutes)
#
# Needs git, docker, kind, kubectl, helm, curl, jq, openssl.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
REF=${REF:-HEAD}
CLUSTER=${CLUSTER:-authn-keycloak}
KC_IMAGE=${KC_IMAGE:-quay.io/keycloak/keycloak:26.4}
WORKDIR=${WORKDIR:-${TMPDIR:-/tmp}/authn-e2e-keycloak}
mkdir -p "$WORKDIR"
export KUBECONFIG=$WORKDIR/kubeconfig LC_ALL=C

step() { printf '\n===== %s  [%s]\n' "$*" "$(date -u +%H:%M:%S)"; }
die() { echo "kind.sh: $*" >&2; exit 1; }

# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  if [[ "${KEEP:-0}" == 1 ]]; then echo "kept kind cluster $CLUSTER (KUBECONFIG=$KUBECONFIG)"
  else kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 && echo "deleted kind cluster $CLUSTER"; fi
}
trap cleanup EXIT

step "kind cluster $CLUSTER"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null || die "kind create"
kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1

SHA=$(git -C "$REPO" rev-parse --short "$REF^{commit}") || die "unknown ref $REF"
step "authn $REF ($SHA): build from git archive, load"
SRC=$WORKDIR/src; rm -rf "$SRC"; mkdir -p "$SRC"
git -C "$REPO" archive "$REF" go/authn helm/authn | tar -x -C "$SRC" || die "git archive $REF"
docker build -q -t "authn:e2e-$SHA" "$SRC/go/authn" >/dev/null || die "docker build"
kind load docker-image "authn:e2e-$SHA" --name "$CLUSTER" >/dev/null || die "kind load authn"
docker image inspect "$KC_IMAGE" >/dev/null 2>&1 || docker pull -q "$KC_IMAGE" >/dev/null || die "pull $KC_IMAGE"
kind load docker-image "$KC_IMAGE" --name "$CLUSTER" >/dev/null || die "kind load $KC_IMAGE"
sed -E "s/CHART_VERSION/0.0.0-e2e/g; s/APP_VERSION/0.0.0-e2e/g" "$SRC/helm/authn/Chart.yaml" > "$SRC/Chart.yaml" && mv "$SRC/Chart.yaml" "$SRC/helm/authn/Chart.yaml"

NS=krateo-system KC_IMAGE=$KC_IMAGE KC_PULL_POLICY=Never WORKDIR=$WORKDIR \
  AUTHN_CHART=$SRC/helm/authn CRDS_DIR=$SRC/go/authn/crds \
  AUTHN_HELM_ARGS="--set image.registry= --set image.repository=authn --set image.tag=e2e-$SHA --set image.pullPolicy=Never" \
  "$HERE/cluster.sh"
