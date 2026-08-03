#!/bin/bash

[ ! -f .env ] || export $(grep -v '^#' .env | xargs)

kubectl create namespace krateo-system || true
kubectl apply -f crds/
kubectl apply -f testdata/github.yaml
kubectl create secret generic github \
    --from-literal=clientSecret=${CLIENT_SECRET} \
    --namespace krateo-system || true

go run main.go -kubeconfig ${HOME}/.kube/config