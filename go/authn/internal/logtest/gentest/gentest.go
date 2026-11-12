// Package gentest checks that a login route hands its request logger to the
// generator (kubeconfig.Logger), so the issuance's lines carry the request's
// session.id and join its audit record.
package gentest

import (
	"testing"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
)

// Line is what Generator logs, through the route's logger, on each issuance.
const Line = "issuance logged with the request's logger"

// Generator wraps a Generator. Each issuance logs Line with the logger the
// route passed, or fails T when the route passed none.
type Generator struct {
	kubeconfig.Generator
	T testing.TB
}

func (g Generator) log(opts []kubeconfig.IssueOption) {
	o := kubeconfig.NewIssueOptions(opts...)
	if o.Log == nil {
		g.T.Errorf("the route issued without its request logger (kubeconfig.Logger)")
		return
	}
	o.Log.Info().Msg(Line)
}

func (g Generator) Generate(s storage.Strategy, u userinfo.Info, opts ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	g.log(opts)
	return g.Generator.Generate(s, u, opts...)
}

func (g Generator) GenerateStepUp(s storage.Strategy, u userinfo.Info, ttl time.Duration, opts ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	g.log(opts)
	return g.Generator.GenerateStepUp(s, u, ttl, opts...)
}
