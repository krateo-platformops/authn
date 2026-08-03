#!/bin/bash
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

${SCRIPT_DIR}/kind-down.sh
${SCRIPT_DIR}/kind-up.sh


IMAGE_NAME="authn"
IMAGE_TAG="latest"
KIND_CLUSTER_NAME="kind"  
MANIFEST_PATH="./manifests/deploy.local.yaml"


echo "Building docker image..."
docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .


echo "Loading docker image into cluster..."
kind load docker-image ${IMAGE_NAME}:${IMAGE_TAG} --name ${KIND_CLUSTER_NAME}


echo "Applying manifests..."
kubectl apply -f "${MANIFEST_PATH}"

echo "Deployment completed."