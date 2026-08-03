#!/bin/bash

CLUSTER="$(kubectl config view --raw -o json | jq -r '."current-context" as $ctx | .contexts[] | select(.name == $ctx) | .context.cluster')"
SERVER="$(kubectl config view --raw -o json | jq -r '.clusters[] | select(.name == "'${CLUSTER}'") | .cluster.server')"
CA_DATA="$(kubectl config view --raw -o json | jq -r '.clusters[] | select(.name == "'${CLUSTER}'") | .cluster."certificate-authority-data"')"

export AUTHN_DEBUG=true
export AUTHN_DUMP_ENV=true
export AUTHN_PORT=8181
export AUTHN_KUBECONFIG_CACRT=$CA_DATA
export AUTHN_KUBECONFIG_CLUSTER_NAME=$CLUSTER
export AUTHN_KUBECONFIG_SERVER_URL=$SERVER
export AUTHN_NAMESPACE=demo-system

kubectl apply -f crds/
kubectl apply -f testdata/ns.yaml
kubectl apply -f testdata/basic.yaml


go run main.go -jwt-sign-key 'AbbraCadabbra' -kubeconfig ${HOME}/.kube/config
