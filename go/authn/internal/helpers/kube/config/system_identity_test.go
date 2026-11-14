package config

import (
	"context"
	"testing"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// No strategy, in either naming mode, is issued a Kubernetes system identity:
// neither group snowplow's RBAC evaluation keys on (system:authenticated,
// system:unauthenticated), nor a system: username (system:anonymous among
// them). snowplow adds system:authenticated to a token's groups unless they
// hold system:unauthenticated or the username is system:anonymous
// (snowplow#1342), which is safe only because authn never issues these.
func TestNoStrategyIsIssuedASystemIdentity(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	strategies := []storage.Strategy{storage.StrategyBasic, storage.StrategyLDAP, storage.StrategyOAuth,
		storage.StrategyOIDC, storage.StrategyServiceAccount}
	for _, naming := range []storage.Naming{{}, exact} {
		for _, strategy := range strategies {
			gen := &kubeconfigGenerator{lookup: &namesLookup{}, log: zerolog.Nop(), naming: naming}
			for _, g := range []string{"system:authenticated", "system:unauthenticated"} {
				_, err := gen.Generate(strategy, userAs("alice", "kc", "1", g))
				assert.Equal(t, RefusalSystemGroup, RefusalOf(err), "exact=%v %s group %s", naming.Exact, strategy, g)
			}
			for _, name := range []string{"system:anonymous", "system:serviceaccount:kube-system:default", "system:kube-scheduler"} {
				_, err := gen.Generate(strategy, userAs(name, "kc", "1"))
				assert.Equal(t, RefusalReserved, RefusalOf(err), "exact=%v %s user %s", naming.Exact, strategy, name)
			}
		}
	}
}

// The exchange runs the same guard, for whichever strategy it is given.
func TestNoExchangeVouchesForASystemUsername(t *testing.T) {
	for _, strategy := range []storage.Strategy{storage.StrategyBasic, storage.StrategyOIDC} {
		_, err := VouchForExchange(context.Background(), &fakeLookup{}, storage.Naming{}, zerolog.Nop(),
			strategy, userAs("system:anonymous", "kc", "1"))
		assert.Equal(t, RefusalReserved, RefusalOf(err), "%s", strategy)
	}
}
