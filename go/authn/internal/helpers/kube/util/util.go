package util

import (
	"fmt"
	"os"
	"strings"
)

const (
	NamespaceEnvVar = "POD_NAMESPACE"
)

// ErrNoNamespace indicates that a namespace could not be found for the current
// environment
var ErrNoNamespace = fmt.Errorf("namespace not found for current environment")

// GetOperatorNamespace returns the namespace the operator should be running in.
// add this environment variable in your deployment config
//   - name: POD_NAMESPACE
//     valueFrom:
//     fieldRef:
//     fieldPath: metadata.namespace
func GetOperatorNamespace() (string, error) {
	ns := os.Getenv(NamespaceEnvVar)
	if len(ns) > 0 {
		return ns, nil
	}

	nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoNamespace
		}
		return "", err
	}

	ns = strings.TrimSpace(string(nsBytes))
	return ns, nil
}
