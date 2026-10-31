#!/usr/bin/env bash
# The kind harness for the Keycloak step-up e2e: a kind cluster, authn built
# from a git ref and installed with its helm chart, Keycloak in start-dev, the
# OIDCConfigs; then realm.sh and stepup.sh.
#
#   go/authn/hack/e2e/keycloak/kind.sh
#
# Env:
#   REF=HEAD                  the authn ref to build (git archive of it: uncommitted changes are not included)
#   CLUSTER=authn-keycloak    the kind cluster; it gets its own kubeconfig file in WORKDIR
#   KEEP=0                    1: keep the cluster afterwards
#   KC_IMAGE=quay.io/keycloak/keycloak:26.4
#   WORKDIR=${TMPDIR:-/tmp}/authn-e2e-keycloak
#   SKIP=                     passed to stepup.sh, e.g. "d e" for a quick run
#
# Needs git, docker, kind, kubectl, helm, curl, jq, openssl.
#
# Keycloak runs with KC_HOSTNAME=http://keycloak.<ns>.svc:8080, so its issuer
# is the in-cluster URL for everyone. This script reaches that same URL
# through a port-forward with curl --connect-to (KC_CURL_ARGS), so Host header,
# cookies and issuer are the ones authn sees and nothing is relaxed.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
REF=${REF:-HEAD}
CLUSTER=${CLUSTER:-authn-keycloak}
KC_IMAGE=${KC_IMAGE:-quay.io/keycloak/keycloak:26.4}
WORKDIR=${WORKDIR:-${TMPDIR:-/tmp}/authn-e2e-keycloak}
NS=krateo-system
KC_HOST=keycloak.$NS.svc:8080
mkdir -p "$WORKDIR"
export KUBECONFIG=$WORKDIR/kubeconfig LC_ALL=C

step() { printf '\n===== %s  [%s]\n' "$*" "$(date -u +%H:%M:%S)"; }
die() { echo "kind.sh: $*" >&2; exit 1; }

# Test-only credentials, all inside this throwaway cluster.
export KC_URL=http://$KC_HOST KC_ADMIN_USER=admin KC_ADMIN_PASSWORD=admin-e2e REALM=krateo
export CLIENT_ID=portal CLIENT_SECRET=portal-e2e-secret REDIRECT_URI='http://localhost/auth?kind=oidc'
export TEST_USER=alice TEST_PASSWORD=alice-e2e-pw TOTP_SEED=authn-e2e-totp-seed-0001 TEST_GROUP=devs

PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  if [[ "${KEEP:-0}" == 1 ]]; then echo "kept kind cluster $CLUSTER (KUBECONFIG=$KUBECONFIG)"
  else kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 && echo "deleted kind cluster $CLUSTER"; fi
}
trap cleanup EXIT

step "kind cluster $CLUSTER"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null || die "kind create"
kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1

SHA=$(git -C "$REPO" rev-parse --short "$REF^{commit}") || die "unknown ref $REF"
step "authn $REF ($SHA): build from git archive, load, install"
SRC=$WORKDIR/src; rm -rf "$SRC"; mkdir -p "$SRC"
git -C "$REPO" archive "$REF" go/authn helm/authn | tar -x -C "$SRC" || die "git archive $REF"
docker build -q -t "authn:e2e-$SHA" "$SRC/go/authn" >/dev/null || die "docker build"
kind load docker-image "authn:e2e-$SHA" --name "$CLUSTER" >/dev/null || die "kind load authn"
docker image inspect "$KC_IMAGE" >/dev/null 2>&1 || docker pull -q "$KC_IMAGE" >/dev/null || die "pull $KC_IMAGE"
kind load docker-image "$KC_IMAGE" --name "$CLUSTER" >/dev/null || die "kind load $KC_IMAGE"

kubectl create ns $NS --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if ! kubectl -n $NS get secret authn-jwt-signing-key >/dev/null 2>&1; then
  openssl genrsa 2048 2>/dev/null | kubectl -n $NS create secret generic authn-jwt-signing-key --from-file=private.pem=/dev/stdin >/dev/null
fi
kubectl apply -f "$SRC/go/authn/crds/" >/dev/null || die "CRDs"
sed -E "s/CHART_VERSION/0.0.0-e2e/g; s/APP_VERSION/0.0.0-e2e/g" "$SRC/helm/authn/Chart.yaml" > "$SRC/Chart.yaml" && mv "$SRC/Chart.yaml" "$SRC/helm/authn/Chart.yaml"
helm upgrade --install authn "$SRC/helm/authn" -n $NS \
  --set image.registry="" --set image.repository=authn --set image.tag="e2e-$SHA" --set image.pullPolicy=Never \
  --wait --timeout 4m >/dev/null || die "helm install"
kubectl -n $NS rollout status deploy/authn --timeout=180s

step "Keycloak $KC_IMAGE (start-dev, KC_HOSTNAME=$KC_URL)"
kubectl -n $NS create secret generic keycloak-admin --from-literal=username="$KC_ADMIN_USER" \
  --from-literal=password="$KC_ADMIN_PASSWORD" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: { name: keycloak, namespace: $NS }
spec:
  selector: { matchLabels: { app: keycloak } }
  template:
    metadata: { labels: { app: keycloak } }
    spec:
      containers:
      - name: keycloak
        image: $KC_IMAGE
        imagePullPolicy: Never
        args: ["start-dev"]
        env:
        - { name: KC_BOOTSTRAP_ADMIN_USERNAME, valueFrom: { secretKeyRef: { name: keycloak-admin, key: username } } }
        - { name: KC_BOOTSTRAP_ADMIN_PASSWORD, valueFrom: { secretKeyRef: { name: keycloak-admin, key: password } } }
        - { name: KC_HOSTNAME, value: "$KC_URL" }
        - { name: KC_HEALTH_ENABLED, value: "true" }
        ports: [{ containerPort: 8080 }]
        readinessProbe: { httpGet: { path: /health/ready, port: 9000 }, periodSeconds: 5 }
---
apiVersion: v1
kind: Service
metadata: { name: keycloak, namespace: $NS }
spec: { selector: { app: keycloak }, ports: [{ port: 8080, targetPort: 8080 }] }
EOF
kubectl -n $NS rollout status deploy/keycloak --timeout=300s || die "Keycloak not ready"

# pf <svc> <port>: a port-forward on a free local port, in PORT. Not in a
# subshell, so cleanup can stop it.
pf() {
  local log=$WORKDIR/pf-$1.log
  PORT=""
  kubectl -n $NS port-forward "svc/$1" ":$2" > "$log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 40); do PORT=$(sed -nE 's/.*127\.0\.0\.1:([0-9]+).*/\1/p' "$log" | head -1); [[ -n "$PORT" ]] && break; sleep 0.5; done
  [[ -n "$PORT" ]] || die "port-forward $1: $(cat "$log")"
}
pf keycloak 8080; KPORT=$PORT
pf authn 8082; APORT=$PORT
export KC_CURL_ARGS="--connect-to $KC_HOST:127.0.0.1:$KPORT"
export AUTHN_URL=http://127.0.0.1:$APORT
echo "Keycloak $KC_URL via 127.0.0.1:$KPORT; authn $AUTHN_URL"
# shellcheck disable=SC2086 # KC_CURL_ARGS is a list of words
for _ in $(seq 1 60); do curl -sf -o /dev/null $KC_CURL_ARGS "$KC_URL/realms/master" && break; sleep 2; done

step "realm.sh"
"$HERE/realm.sh" || die "realm.sh"

step "OIDCConfigs keycloak (stepUp maxAge 5m) and keycloak-stale (maxAge 60s, for d and e)"
kubectl -n $NS create secret generic keycloak-portal --from-literal=clientSecret="$CLIENT_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for c in keycloak:5m keycloak-stale:60s; do
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: oidc.authn.krateo.io/v1alpha1
kind: OIDCConfig
metadata: { name: ${c%%:*}, namespace: $NS }
spec:
  discoveryURL: $KC_URL/realms/$REALM/.well-known/openid-configuration
  redirectURI: "$REDIRECT_URI"
  clientID: $CLIENT_ID
  clientSecret: { name: keycloak-portal, namespace: $NS, key: clientSecret }
  stepUp: { acrValues: ["gold"], maxAge: ${c##*:} }
EOF
done

step "stepup.sh"
OIDC_NAME=keycloak OIDC_NAME_STALE=keycloak-stale KUBECTL_CHECKS=1 AUTHN_NAMESPACE=$NS WORKDIR=$WORKDIR/run \
  "$HERE/stepup.sh"
RC=$?

step "authn warnings and errors"
kubectl -n $NS logs deploy/authn | jq -rc 'select(.level=="error" or .level=="warn") | {level, message, error}' 2>/dev/null | sort | uniq -c | head -20
exit $RC
