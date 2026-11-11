package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"go.opentelemetry.io/otel/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// previewTTL bounds how stale a record's preview flag can be. authn writes only
// into its own namespace, whose purpose label does not change in practice; the
// cache keeps a login from costing an extra apiserver read.
const previewTTL = 5 * time.Minute

// EnvServiceAccount names authn's own ServiceAccount; the chart sets it. It is
// the actor of the records of authn's background writes.
const EnvServiceAccount = "POD_SERVICE_ACCOUNT"

// newAudit builds the request and controller audit recorders (AUDIT-4). lp nil
// (the logs pipeline is off) gives recorders that write nothing and read
// nothing.
func newAudit(rc *rest.Config, lp log.LoggerProvider) (*auditlog.Recorder, *auditlog.Controller, error) {
	if lp == nil {
		return auditlog.New(nil, nil), auditlog.NewController(nil, "", nil), nil
	}
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, nil, err
	}
	sa := os.Getenv(EnvServiceAccount)
	if sa == "" {
		return nil, nil, fmt.Errorf("%s is not set: the audit records of authn's own writes need their actor", EnvServiceAccount)
	}
	cli, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, nil, err
	}
	labels := func(ctx context.Context, namespace string) (map[string]string, error) {
		n, err := cli.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return n.Labels, nil
	}
	preview := auditlog.CachedPreview(labels, previewTTL)
	return auditlog.New(lp, preview),
		auditlog.NewController(lp, "system:serviceaccount:"+ns+":"+sa, preview), nil
}
