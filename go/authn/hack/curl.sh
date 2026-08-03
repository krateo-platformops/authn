#!/bin/bash

# Path to kubeconfig file
KUBECONFIG="luca.json"

# API Object Group
GROUP=widgets.ui.krateo.io
# API Object Version
VERSION=v1alpha1
# API Object Resource
RESOURCE=cardtemplates
# API Object Namespace
NAMESPACE=dev-system


# 💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀
# 💀💀💀 DO NOT EDIT THIS!! 💀💀💀
# 💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀
CLUSTER="$(cat ${KUBECONFIG} | jq -r '."current-context" as $ctx | .contexts[] | select(.name == $ctx) | .context.cluster')"
USER="$(cat ${KUBECONFIG} | jq -r '."current-context" as $ctx | .contexts[] | select(.name == $ctx) | .context.user')"

SERVER="$(cat ${KUBECONFIG} | jq -r '.clusters[] | select(.name == "'${CLUSTER}'") | .cluster.server')"
PROXY_URL="$(cat ${KUBECONFIG} | jq -r '.clusters[] | select(.name == "'${CLUSTER}'") | .cluster."proxy-url"')"

CA_DATA="$(cat ${KUBECONFIG} | jq -r '.clusters[] | select(.name == "'${CLUSTER}'") | .cluster."certificate-authority-data"' | base64 -d)"
CRT_DATA=$(cat ${KUBECONFIG} | jq -r '.users[] | select(.name == "'${USER}'") | .user."client-certificate-data"' | base64 -d)
KEY_DATA=$(cat ${KUBECONFIG} | jq -r '.users[] | select(.name == "'${USER}'") | .user."client-key-data"' | base64 -d)

curl --proxy "${PROXY_URL}" \
  --proxy-cacert <(echo "${CA_DATA}") --proxy-cert <(echo "${CRT_DATA}") --proxy-key <(echo "${KEY_DATA}") \
  --cacert <(echo "${CA_DATA}") --cert <(echo "${CRT_DATA}") --key <(echo "${KEY_DATA}") \
  -H "Accept: application/json" \
  "${SERVER}/apis/${GROUP}/${VERSION}/namespaces/${NAMESPACE}/${RESOURCE}"