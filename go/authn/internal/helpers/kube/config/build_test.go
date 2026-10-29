package config

import (
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// An identity carrying a reserved group can only have been built around
// userinfo's guard. The generator refuses it before contacting the cluster.
func TestGenerateRefusesReservedGroups(t *testing.T) {
	gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"})
	user := &userinfo.DefaultUser{Name: "alice", ID: "1", Groups: []string{"devs", "krateo:loa:2"}}

	_, _, err := gen.Generate(storage.StrategyOIDC, user)
	require.ErrorContains(t, err, `group "krateo:loa:2" is reserved`)
}

// A step-up credential exists to carry a krateo:loa: group. Without one, the
// caller didn't go through userinfo.NewStepUpUser, so it is refused.
func TestGenerateStepUpRequiresAReservedGroup(t *testing.T) {
	gen := NewGenerator(&rest.Config{Host: "https://unreachable.invalid"})
	user := userinfo.NewDefaultUser("alice", "1", []string{"devs"}, nil)

	_, err := gen.GenerateStepUp(storage.StrategyOIDC, user, 15*time.Minute)
	require.ErrorContains(t, err, "must carry a krateo:loa: group")
}
