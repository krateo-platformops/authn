package userinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// No identity source may assert a krateo:loa: group: admission policies trust
// it as proof of a step-up login, which only authn grants.
func TestReservedGroupsAreDropped(t *testing.T) {
	cases := []struct {
		name    string
		groups  []string
		kept    []string
		dropped []string
	}{
		{name: "nothing reserved", groups: []string{"devs", "ops"}, kept: []string{"devs", "ops"}},
		{name: "loa group dropped", groups: []string{"devs", "krateo:loa:2"}, kept: []string{"devs"}, dropped: []string{"krateo:loa:2"}},
		{name: "any level dropped", groups: []string{"krateo:loa:1", "krateo:loa:3"}, dropped: []string{"krateo:loa:1", "krateo:loa:3"}},
		{name: "similar names kept", groups: []string{"krateo:loader", "krateo:loa", "x:krateo:loa:2"},
			kept: []string{"krateo:loader", "krateo:loa", "x:krateo:loa:2"}},
		{name: "no groups", groups: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := NewDefaultUser("alice", "1", tc.groups, nil)
			assert.Equal(t, tc.kept, u.GetGroups())
			assert.Equal(t, tc.dropped, u.DroppedGroups())

			u = NewDefaultUser("alice", "1", nil, nil)
			u.SetGroups(tc.groups)
			assert.Equal(t, tc.kept, u.GetGroups(), "SetGroups applies the same guard")
			assert.Equal(t, tc.dropped, u.DroppedGroups())
		})
	}
}
