package main

import (
	"time"

	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/certrenewal"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/identitybackfill"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

// componentConfig is what main builds the components that write or read
// session Secrets from.
type componentConfig struct {
	RestConfig *rest.Config
	// Naming is how session Secrets are named (sessionNaming): every
	// component below gets it, so none can name or read a Secret otherwise.
	Naming storage.Naming
	Log    zerolog.Logger
	Audit  *auditlog.Controller

	// The login generator's.
	KubernetesURL string
	ClusterName   string
	CertDuration  time.Duration

	// authn's own identity's, for the renewer and the backfill.
	SelfUsername        string
	StorageNamespace    string
	ServiceCertDuration time.Duration
	RenewalThreshold    float64
}

// components are the session-Secret components main runs: the login
// generator, and the options of the renewer and the backfill, which the
// leader builds from them (the backfill's namespaces are resolved when it
// runs).
type components struct {
	Generator kubeconfig.Generator
	Renewer   certrenewal.Options
	Backfill  identitybackfill.Options
}

// newComponents builds them, each with c.Naming. main calls only this, so
// TestNewComponentsGiveEveryComponentTheNaming pins the wiring.
func newComponents(c componentConfig) components {
	return components{
		Generator: kubeconfig.NewGenerator(c.RestConfig,
			kubeconfig.Naming(c.Naming),
			kubeconfig.KubernetesURL(c.KubernetesURL),
			kubeconfig.CertDuration(c.CertDuration),
			kubeconfig.ClusterName(c.ClusterName),
			kubeconfig.Log(c.Log),
		),
		Renewer: certrenewal.Options{
			RestConfig: c.RestConfig,
			Namespace:  c.StorageNamespace,
			CAData:     string(c.RestConfig.CAData),
			ServerURL:  c.KubernetesURL,
			Username:   c.SelfUsername,
			Groups:     []string{"authn"},
			Duration:   c.ServiceCertDuration,
			Threshold:  c.RenewalThreshold,
			Log:        c.Log,
			Audit:      c.Audit,
			Naming:     c.Naming,
		},
		Backfill: identitybackfill.Options{
			RestConfig:   c.RestConfig,
			SelfUsername: c.SelfUsername,
			Log:          c.Log,
			Audit:        c.Audit,
			Naming:       c.Naming,
		},
	}
}
