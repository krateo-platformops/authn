#!/usr/bin/env bash
# The Keycloak step-up e2e on an existing cluster, the one in KUBECONFIG: authn
# installed with helm, Keycloak in start-dev and the OIDCConfigs, all in
# namespace NS; then realm.sh and stepup.sh. kind.sh runs it on a kind cluster
# with authn built from git. On any other cluster (GKE, ...) run it directly,
# against a published release:
#
#   KUBECONFIG=<file> NS=authn-e2e AUTHN_VERSION=0.31.1 go/authn/hack/e2e/keycloak/cluster.sh
#
# Env:
#   KUBECONFIG                required, even for ~/.kube/config: this script installs into that cluster
#   NS=krateo-system          namespace for authn, Keycloak, the OIDCConfigs and the user Secrets (created if missing)
#   AUTHN_VERSION=            a published release: chart oci://ghcr.io/krateo-platformops/charts/authn
#                             and the CRDs of the authn-crds chart, both at that version
#   AUTHN_CHART=              or a local chart directory, with CRDS_DIR and AUTHN_HELM_ARGS (kind.sh sets them)
#   AUTHN_IMAGE_DIGEST=       optional: fail unless the running authn pod's imageID ends with this (sha256:...)
#   JWT_KID=authn-e2e-key-1   jwt.kid; the signing key Secret is created once, as authn-jwt-signing-key
#   KC_IMAGE=quay.io/keycloak/keycloak:26.4   KC_PULL_POLICY=IfNotPresent
#   WORKDIR=${TMPDIR:-/tmp}/authn-e2e-keycloak
#   SKIP=                     passed to stepup.sh, e.g. "d e f" for a quick run (f, the
#                             step-up sweep, waits for a real expiry: about 20 minutes)
#   UNINSTALL=0               1: helm uninstall authn and delete NS at the end. The CRDs are
#                             applied, never deleted: other installs may use them.
#
# Needs kubectl, helm, curl, jq, openssl.
#
# Keycloak runs with KC_HOSTNAME=http://keycloak.<NS>.svc:8080, so its issuer
# is the in-cluster URL for everyone. This script reaches that same URL
# through a port-forward with curl --connect-to (KC_CURL_ARGS), so Host header,
# cookies and issuer are the ones authn sees and nothing is relaxed.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
: "${KUBECONFIG:?set KUBECONFIG to the cluster to install into}"
NS=${NS:-krateo-system}
AUTHN_VERSION=${AUTHN_VERSION:-}
AUTHN_CHART=${AUTHN_CHART:-}
CRDS_DIR=${CRDS_DIR:-}
AUTHN_IMAGE_DIGEST=${AUTHN_IMAGE_DIGEST:-}
JWT_KID=${JWT_KID:-authn-e2e-key-1}
KC_IMAGE=${KC_IMAGE:-quay.io/keycloak/keycloak:26.4}
KC_PULL_POLICY=${KC_PULL_POLICY:-IfNotPresent}
WORKDIR=${WORKDIR:-${TMPDIR:-/tmp}/authn-e2e-keycloak}
KC_HOST=keycloak.$NS.svc:8080
read -ra HELM_X <<<"${AUTHN_HELM_ARGS:-}"
mkdir -p "$WORKDIR"
export KUBECONFIG LC_ALL=C

step() { printf '\n===== %s  [%s]\n' "$*" "$(date -u +%H:%M:%S)"; }
die() { echo "cluster.sh: $*" >&2; exit 1; }
[[ -n "$AUTHN_VERSION" || -n "$AUTHN_CHART" ]] || die "set AUTHN_VERSION (published chart) or AUTHN_CHART (local chart)"

# Test-only credentials, all inside the test namespace.
export KC_URL=http://$KC_HOST KC_ADMIN_USER=admin KC_ADMIN_PASSWORD=admin-e2e REALM=krateo
export CLIENT_ID=portal CLIENT_SECRET=portal-e2e-secret REDIRECT_URI='http://localhost/auth?kind=oidc'
export TEST_USER=alice TEST_PASSWORD=alice-e2e-pw TOTP_SEED=authn-e2e-totp-seed-0001 TEST_GROUP=devs
# f's rewrite check: a second user, same password and TOTP seed.
REWRITE_USER=bob

PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  for p in "${PIDS[@]}"; do pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null || true; done
  if [[ "${UNINSTALL:-0}" == 1 ]]; then
    helm uninstall authn -n "$NS" --wait >/dev/null 2>&1 && echo "uninstalled authn from $NS"
    kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 && echo "deleting namespace $NS"
  fi
}
trap cleanup EXIT

kubectl get --raw /version >/dev/null || die "no cluster at KUBECONFIG=$KUBECONFIG"
echo "cluster: $(kubectl config current-context) (KUBECONFIG=$KUBECONFIG), namespace $NS"

step "authn ${AUTHN_VERSION:+$AUTHN_VERSION (published chart)}${AUTHN_CHART:+$AUTHN_CHART}: CRDs, signing key, helm install"
kubectl create ns "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if ! kubectl -n "$NS" get secret authn-jwt-signing-key >/dev/null 2>&1; then
  openssl genrsa 2048 2>/dev/null | kubectl -n "$NS" create secret generic authn-jwt-signing-key --from-file=private.pem=/dev/stdin >/dev/null
fi
if [[ -n "$AUTHN_CHART" ]]; then
  CHART=("$AUTHN_CHART")
  kubectl apply -f "${CRDS_DIR:?CRDS_DIR is required with AUTHN_CHART}" >/dev/null || die "CRDs"
else
  CHART=(oci://ghcr.io/krateo-platformops/charts/authn --version "$AUTHN_VERSION")
  helm template authn-crds oci://ghcr.io/krateo-platformops/charts/authn-crds --version "$AUTHN_VERSION" 2>/dev/null \
    | kubectl apply -f - >/dev/null || die "CRDs (authn-crds $AUTHN_VERSION)"
fi
helm upgrade --install authn "${CHART[@]}" -n "$NS" --set jwt.kid="$JWT_KID" "${HELM_X[@]}" \
  --wait --timeout 4m >/dev/null || die "helm install"
kubectl -n "$NS" rollout status deploy/authn --timeout=180s
IMAGE_ID=$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=authn -o jsonpath='{range .items[*]}{.status.containerStatuses[0].imageID}{"\n"}{end}' | sort -u)
echo "authn image: $(kubectl -n "$NS" get deploy/authn -o jsonpath='{.spec.template.spec.containers[0].image}'), running imageID: $IMAGE_ID"
if [[ -n "$AUTHN_IMAGE_DIGEST" && "$IMAGE_ID" != *"@$AUTHN_IMAGE_DIGEST" ]]; then
  die "running imageID '$IMAGE_ID' is not @$AUTHN_IMAGE_DIGEST"
fi

step "Keycloak $KC_IMAGE (start-dev, KC_HOSTNAME=$KC_URL)"
kubectl -n "$NS" create secret generic keycloak-admin --from-literal=username="$KC_ADMIN_USER" \
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
        imagePullPolicy: $KC_PULL_POLICY
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
kubectl -n "$NS" rollout status deploy/keycloak --timeout=300s || die "Keycloak not ready"

# pf <svc> <port>: a port-forward on a free local port, in PORT. It is
# restarted on the same port if it drops (f leaves it idle for ~10 minutes).
# Not in a command substitution, so cleanup can stop it.
pf() {
  local log=$WORKDIR/pf-$1.log
  PORT=""; : > "$log"
  ( p=""; while :; do
      kubectl -n "$NS" port-forward "svc/$1" "$p:$2" >> "$log" 2>&1
      p=$(sed -nE 's/.*127\.0\.0\.1:([0-9]+).*/\1/p' "$log" | head -1); sleep 1
    done ) &
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
TEST_USER=$REWRITE_USER "$HERE/realm.sh" >/dev/null || die "realm.sh ($REWRITE_USER)"

step "OIDCConfigs keycloak (stepUp maxAge 5m), keycloak-stale (maxAge 60s, for d and e), keycloak-sweep (ttl 10m, for f)"
kubectl -n "$NS" create secret generic keycloak-portal --from-literal=clientSecret="$CLIENT_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for c in keycloak:5m keycloak-stale:60s keycloak-sweep:5m:10m; do
IFS=: read -r name max_age ttl <<<"$c"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: oidc.authn.krateo.io/v1alpha1
kind: OIDCConfig
metadata: { name: $name, namespace: $NS }
spec:
  discoveryURL: $KC_URL/realms/$REALM/.well-known/openid-configuration
  redirectURI: "$REDIRECT_URI"
  clientID: $CLIENT_ID
  clientSecret: { name: keycloak-portal, namespace: $NS, key: clientSecret }
  stepUp: { acrValues: ["gold"], maxAge: $max_age${ttl:+, ttl: $ttl} }
EOF
done

step "stepup.sh"
OIDC_NAME=keycloak OIDC_NAME_STALE=keycloak-stale OIDC_NAME_SWEEP=keycloak-sweep SWEEP_REWRITE_USER=$REWRITE_USER \
  KUBECTL_CHECKS=1 AUTHN_NAMESPACE=$NS AUTHN_SELECTOR=app.kubernetes.io/name=authn WORKDIR=$WORKDIR/run \
  "$HERE/stepup.sh"
RC=$?

step "authn warnings and errors"
kubectl -n "$NS" logs deploy/authn | jq -Rrc 'fromjson? | select(.level=="error" or .level=="warn") | {level, message, error}' 2>/dev/null | sort | uniq -c | head -20
echo "authn running imageID: $IMAGE_ID"
exit $RC
