#!/bin/bash

CLUSTER="$(kubectl config view --raw -o json | jq -r '."current-context" as $ctx | .contexts[] | select(.name == $ctx) | .context.cluster')"
SERVER="$(kubectl config view --raw -o json | jq -r '.clusters[] | select(.name == "'${CLUSTER}'") | .cluster.server')"
CA_DATA="$(kubectl config view --raw -o json | jq -r '.clusters[] | select(.name == "'${CLUSTER}'") | .cluster."certificate-authority-data"')"

export AUTHN_DEBUG=true
export AUTHN_PORT=8181
export AUTHN_KUBECONFIG_CACRT=$CA_DATA
export AUTHN_KUBECONFIG_CLUSTER_NAME=$CLUSTER
export AUTHN_KUBECONFIG_SERVER_URL=$SERVER
export AUTHN_NAMESPACE=demo-system

kubectl apply -f crds/
kubectl apply -f testdata/ns.yaml
kubectl apply -f testdata/basic.yaml


# authn signs with an RSA key read from a file. This one is for this run only and is deleted on exit.
KEY_DIR="$(mktemp -d)"
trap 'rm -rf "${KEY_DIR}"' EXIT
openssl genrsa -out "${KEY_DIR}/private.pem" 2048

go run main.go -jwt-sign-key-file "${KEY_DIR}/private.pem" -jwt-kid krateo-authn-key-1 -kubeconfig "${HOME}/.kube/config"
