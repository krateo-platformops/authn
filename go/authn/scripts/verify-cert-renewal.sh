#!/usr/bin/env bash
# Verify client certificate renewal on the cluster kubectl currently points at.
#
# Certificate handling differs per Kubernetes distribution: whether
# spec.expirationSeconds is honoured at all, what --cluster-signing-duration
# caps it to, and how/when the signer CA rotates. None of that can be reasoned
# about from the code, so this script measures it. Run it once per flavour
# (kind, minikube, k3s/k3d, EKS, AKS, GKE, OpenShift) and record the output.
#
# It answers three questions:
#   1. What NotAfter did this signer actually grant?
#   2. Does renewal fire before expiry?
#   3. Is the renewed certificate accepted by the apiserver?
#
# Question 2 is the slow one: by default it only reports when renewal is due.
# Pass --wait to force it now by collapsing the renewal threshold and restarting authn, or
# --short <duration> to reinstall authn with a lifetime short enough to watch a
# real renewal end to end (recommended: 15m, so the whole cycle takes ~10m).
#
# Usage:
#   go/authn/scripts/verify-cert-renewal.sh [-n NAMESPACE] [-d DEPLOYMENT] [--wait] [--short DURATION]

set -euo pipefail

NAMESPACE="${NAMESPACE:-krateo-system}"
DEPLOYMENT="${DEPLOYMENT:-authn}"
SECRET="authn-clientconfig"
FORCE=0
SHORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    -d|--deployment) DEPLOYMENT="$2"; shift 2 ;;
    --wait)         FORCE=1; shift ;;
    --short)        SHORT="$2"; shift 2 ;;
    -h|--help)      sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for bin in kubectl openssl; do
  command -v "$bin" >/dev/null || { echo "missing required tool: $bin" >&2; exit 1; }
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m  %s\n' "$*"; FAILED=1; }
pass() { printf '\033[32mok\033[0m    %s\n' "$*"; }
FAILED=0

# ---------------------------------------------------------------- distribution
say "cluster"
kubectl version -o json 2>/dev/null | sed -n 's/.*"gitVersion": *"\([^"]*\)".*/server: \1/p' | head -1
FLAVOUR="unknown"
if kubectl api-resources --api-group=config.openshift.io 2>/dev/null | grep -q clusterversions; then
  FLAVOUR="openshift"
elif kubectl get nodes -o jsonpath='{.items[0].metadata.labels}' 2>/dev/null | grep -q 'k3s'; then
  FLAVOUR="k3s"
elif kubectl config current-context 2>/dev/null | grep -q '^kind-'; then
  FLAVOUR="kind"
elif kubectl config current-context 2>/dev/null | grep -q 'minikube'; then
  FLAVOUR="minikube"
elif kubectl get nodes -o jsonpath='{.items[0].spec.providerID}' 2>/dev/null | grep -q '^aws'; then
  FLAVOUR="eks"
elif kubectl get nodes -o jsonpath='{.items[0].spec.providerID}' 2>/dev/null | grep -q '^azure'; then
  FLAVOUR="aks"
elif kubectl get nodes -o jsonpath='{.items[0].spec.providerID}' 2>/dev/null | grep -q '^gce'; then
  FLAVOUR="gke"
fi
echo "flavour: $FLAVOUR"

# setting reads the effective value of an authn env var: the Deployment's own
# container env wins over a ConfigMap (that is how Kubernetes resolves it), and
# an unset var falls back to the binary's default.
setting() {
  local key="$1" default="$2" val
  val=$(kubectl -n "$NAMESPACE" get deploy "$DEPLOYMENT" \
    -o jsonpath="{.spec.template.spec.containers[0].env[?(@.name=='$key')].value}" 2>/dev/null)
  [[ -n "$val" ]] || val=$(kubectl -n "$NAMESPACE" get configmap authn \
    -o jsonpath="{.data.$key}" 2>/dev/null)
  echo "${val:-$default}"
}

# --------------------------------------------------------------- optional: short lifetime
if [[ -n "$SHORT" ]]; then
  say "reconfiguring authn for a $SHORT service certificate"
  # Patch the Deployment's container env rather than a ConfigMap: an explicit
  # env entry wins over envFrom, so this works whether authn was deployed from
  # manifests/ or from a chart.
  kubectl -n "$NAMESPACE" set env "deploy/$DEPLOYMENT" \
    AUTHN_SERVICE_CRT_EXPIRES_IN="$SHORT"
  kubectl -n "$NAMESPACE" delete secret "$SECRET" --ignore-not-found
  kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOYMENT" --timeout=180s
fi

# ---------------------------------------------------------------- 1. granted window
say "1. granted validity window"
kubectl -n "$NAMESPACE" get secret "$SECRET" >/dev/null || {
  echo "secret $SECRET not found in $NAMESPACE" >&2; exit 1; }

CERT="$(mktemp)"; trap 'rm -f "$CERT" "${CERT}.key" "${CERT}.ca" "${CERT}.kubeconfig"' EXIT
kubectl -n "$NAMESPACE" get secret "$SECRET" \
  -o jsonpath='{.data.client-certificate-data}' | base64 -d | base64 -d > "$CERT"

openssl x509 -in "$CERT" -noout -subject -dates

NOT_BEFORE_EPOCH=$(date -u -j -f "%b %e %T %Y" "$(openssl x509 -in "$CERT" -noout -startdate | cut -d= -f2 | sed 's/ GMT//')" +%s 2>/dev/null \
  || date -u -d "$(openssl x509 -in "$CERT" -noout -startdate | cut -d= -f2)" +%s)
NOT_AFTER_EPOCH=$(date -u -j -f "%b %e %T %Y" "$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2 | sed 's/ GMT//')" +%s 2>/dev/null \
  || date -u -d "$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)" +%s)
NOW=$(date -u +%s)

GRANTED_H=$(( (NOT_AFTER_EPOCH - NOT_BEFORE_EPOCH) / 3600 ))
REQUESTED=$(setting AUTHN_SERVICE_CRT_EXPIRES_IN 8760h)
echo "requested: $REQUESTED   granted: ${GRANTED_H}h"

# The annotation is what makes the granted window observable without openssl;
# it is the headline deliverable of the change.
ANN=$(kubectl -n "$NAMESPACE" get secret "$SECRET" \
  -o jsonpath='{.metadata.annotations.authn\.krateo\.io/certificate-not-after}')
if [[ -n "$ANN" ]]; then
  pass "not-after annotation present: $ANN"
else
  fail "not-after annotation missing (authn needs get+update on secrets; see manifests/deploy.local.yaml)"
fi

if (( NOT_AFTER_EPOCH <= NOW )); then
  fail "the stored certificate is ALREADY EXPIRED"
else
  pass "valid for $(( (NOT_AFTER_EPOCH - NOW) / 3600 ))h more"
fi

# --------------------------------------------------------------- 2. renewal fires
say "2. renewal fires before expiry"
THRESHOLD=$(setting AUTHN_CRT_RENEWAL_THRESHOLD 0.66)
RENEW_AT=$(awk -v nb="$NOT_BEFORE_EPOCH" -v na="$NOT_AFTER_EPOCH" -v t="$THRESHOLD" 'BEGIN{printf "%d", nb + (na-nb)*t}')
echo "threshold: $THRESHOLD   renewal due: $(date -u -r "$RENEW_AT" 2>/dev/null || date -u -d "@$RENEW_AT")"

SERIAL_BEFORE=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)

if (( FORCE )); then
  # Drive the renewal point into the past by collapsing the threshold, then
  # restart so the loop re-derives it. This exercises the real "passed its
  # renewal point" branch.
  #
  # Rewinding the not-after ANNOTATION would do nothing: the loop decides off the
  # stored certificate, never the annotation, so a rewound annotation is ignored
  # and the certificate is judged current.
  #
  # While the override is in place a re-issue happens every minSleep (a minute),
  # since each fresh certificate is immediately due again — so it is restored as
  # soon as a new serial appears.
  echo "forcing: collapsing the renewal threshold and restarting authn"
  kubectl -n "$NAMESPACE" set env "deploy/$DEPLOYMENT" AUTHN_CRT_RENEWAL_THRESHOLD=0.0001
  kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOYMENT" --timeout=180s
  # Restore on any exit path, not just the happy one.
  trap 'kubectl -n "$NAMESPACE" set env "deploy/$DEPLOYMENT" AUTHN_CRT_RENEWAL_THRESHOLD- >/dev/null 2>&1 || true; rm -f "$CERT" "${CERT}.key" "${CERT}.ca" "${CERT}.kubeconfig"' EXIT
fi

if (( FORCE )) || (( NOW >= RENEW_AT )); then
  echo "waiting up to 5m for a new serial..."
  for _ in $(seq 1 60); do
    sleep 5
    kubectl -n "$NAMESPACE" get secret "$SECRET" \
      -o jsonpath='{.data.client-certificate-data}' | base64 -d | base64 -d > "$CERT"
    SERIAL_NOW=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)
    [[ "$SERIAL_NOW" != "$SERIAL_BEFORE" ]] && break
  done
  if [[ "${SERIAL_NOW:-$SERIAL_BEFORE}" != "$SERIAL_BEFORE" ]]; then
    pass "certificate re-issued (serial $SERIAL_BEFORE -> $SERIAL_NOW)"
  else
    fail "renewal did not fire; check: kubectl -n $NAMESPACE logs deploy/$DEPLOYMENT | grep certificate"
  fi
else
  echo "not due yet — re-run with --wait to force, or --short 15m to watch a real cycle"
fi

# ------------------------------------------------- 3. the apiserver accepts it
say "3. the renewed certificate authenticates"
# Both cert and key are stored base64-of-base64: the Secret encodes the value,
# and the value is itself the base64-PEM a kubeconfig carries. The CA is stored
# the same way (plumbing's kubeutil.CACrt base64-encodes the PEM before storing).
kubectl -n "$NAMESPACE" get secret "$SECRET" -o jsonpath='{.data.client-key-data}' | base64 -d | base64 -d > "${CERT}.key"
kubectl -n "$NAMESPACE" get secret "$SECRET" -o jsonpath='{.data.certificate-authority-data}' | base64 -d | base64 -d > "${CERT}.ca"
SERVER=$(kubectl -n "$NAMESPACE" get secret "$SECRET" -o jsonpath='{.data.server-url}' | base64 -d)

# Build a standalone kubeconfig from the Secret rather than overriding flags on
# the ambient one: with the admin context still in play, an ambient token could
# authenticate the call and mask a certificate the apiserver actually rejected.
KUBECONFIG_OUT="${CERT}.kubeconfig"
kubectl config --kubeconfig="$KUBECONFIG_OUT" set-cluster verify \
  --server="$SERVER" --certificate-authority="${CERT}.ca" --embed-certs=true >/dev/null
kubectl config --kubeconfig="$KUBECONFIG_OUT" set-credentials verify \
  --client-certificate="$CERT" --client-key="${CERT}.key" --embed-certs=true >/dev/null
kubectl config --kubeconfig="$KUBECONFIG_OUT" set-context verify \
  --cluster=verify --user=verify >/dev/null
kubectl config --kubeconfig="$KUBECONFIG_OUT" use-context verify >/dev/null

# A SelfSubjectReview echoes back the identity the apiserver derived from the
# presented certificate: proof both that the certificate is accepted and that
# CN/O still map to the expected user and groups.
if OUT=$(kubectl --kubeconfig="$KUBECONFIG_OUT" auth whoami -o json 2>&1); then
  pass "accepted by the apiserver"
  echo "$OUT" | grep -E '"username"|"groups"' || true
elif kubectl --kubeconfig="$KUBECONFIG_OUT" auth can-i get secrets -n "$NAMESPACE" >/dev/null 2>&1; then
  # `auth whoami` needs SelfSubjectReview (k8s >= 1.27); any authenticated call
  # proves the same point. can-i answering "no" still means authentication
  # succeeded — only a transport/x509 error is a failure here.
  pass "accepted by the apiserver (via SelfSubjectAccessReview)"
else
  fail "the apiserver rejected the certificate: $OUT"
fi

# ------------------------------------------------------------------- verdict
say "record this row"
printf '| %-10s | requested %-6s | granted %-6s | renewal %-8s | apiserver %-8s |\n' \
  "$FLAVOUR" "$REQUESTED" "${GRANTED_H}h" \
  "$( ((FAILED)) && echo see-above || echo ok )" \
  "$( ((FAILED)) && echo see-above || echo ok )"

exit "$FAILED"
