package ldap

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	return string(b)
}

func group(dn string, attrs map[string][]string) *ldap.Entry { return ldap.NewEntry(dn, attrs) }

// The group search follows spec.groupSearch (#72): its base DN, its filter
// rendered for the user who bound, and its name attribute. Every value
// substituted into a filter is escaped. The expected filters are written out
// by hand, not computed with ldap.EscapeFilter.
func TestGroupSearch(t *testing.T) {
	cases := []struct {
		name        string
		username    string
		userDN      string
		userOU      []string
		groupSearch string
		groups      []*ldap.Entry

		userFilter string // the user search's filter, when the case checks it
		baseDN     string
		filter     string
		attrs      []string
		want       []string
	}{
		{
			name:   "default: member or uniqueMember equal to the user's DN",
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name: "default, given empty fields", groupSearch: `{"baseDN":"","filter":"","nameAttribute":""}`,
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name:   "default, with a DN holding filter specials",
			userDN: `cn=O\2CBrien (ops)*,ou=people,dc=corp`,
			baseDN: "dc=example",
			filter: `(|(member=cn=O\5c2CBrien \28ops\29\2a,ou=people,dc=corp)(uniqueMember=cn=O\5c2CBrien \28ops\29\2a,ou=people,dc=corp))`,
			attrs:  []string{"cn"}, want: []string{"devs"},
		},
		{
			name:   "a DN can't inject a filter",
			userDN: `uid=x)(objectClass=*,dc=corp`,
			baseDN: "dc=example",
			filter: `(|(member=uid=x\29\28objectClass=\2a,dc=corp)(uniqueMember=uid=x\29\28objectClass=\2a,dc=corp))`,
			attrs:  []string{"cn"}, want: []string{"devs"},
		},
		{
			name:        "posixGroup: memberUid equal to the username",
			groupSearch: `{"filter":"(&(objectClass=posixGroup)(memberUid={{.Username}}))"}`,
			baseDN:      "dc=example", filter: "(&(objectClass=posixGroup)(memberUid=alice))",
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name:        "Active Directory nested groups (LDAP_MATCHING_RULE_IN_CHAIN)",
			groupSearch: `{"filter":"(member:1.2.840.113556.1.4.1941:={{.DN}})"}`,
			baseDN:      "dc=example", filter: "(member:1.2.840.113556.1.4.1941:=uid=alice,dc=example)",
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name:        "a username can't inject a filter",
			username:    `a*)(uid=*)\`,
			groupSearch: `{"filter":"(memberUid={{.Username}})"}`,
			userFilter:  `(|(cn=a\2a\29\28uid=\2a\29\5c)(uid=a\2a\29\28uid=\2a\29\5c)(userPrincipalName=a\2a\29\28uid=\2a\29\5c)(mail=a\2a\29\28uid=\2a\29\5c))`,
			baseDN:      "dc=example", filter: `(memberUid=a\2a\29\28uid=\2a\29\5c)`,
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name:        "custom base DN and name attribute",
			groupSearch: `{"baseDN":"ou=groups,dc=corp","nameAttribute":"displayName"}`,
			groups: []*ldap.Entry{
				group("cn=devs,ou=groups,dc=corp", map[string][]string{"cn": {"devs"}, "displayName": {"Developers"}}),
				group("cn=ops,ou=groups,dc=corp", map[string][]string{"cn": {"ops"}}),                // no displayName: skipped
				group("cn=admins,ou=groups,dc=corp", map[string][]string{"displayname": {"Admins"}}), // names are case-insensitive
			},
			baseDN: "ou=groups,dc=corp", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"displayName"}, want: []string{"Developers", "Admins"},
		},
		{
			name: "a group without the name attribute is skipped",
			groups: []*ldap.Entry{
				group("cn=devs,dc=example", map[string][]string{"cn": {"devs"}}),
				group("ou=nameless,dc=example", map[string][]string{"description": {"no cn"}}),
				group("cn=empty,dc=example", map[string][]string{"cn": {""}}),
			},
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name: "duplicate names are kept once, in order",
			groups: []*ldap.Entry{
				group("cn=devs,ou=eu,dc=example", map[string][]string{"cn": {"devs"}}),
				group("cn=ops,dc=example", map[string][]string{"cn": {"ops"}}),
				group("cn=devs,ou=us,dc=example", map[string][]string{"cn": {"devs"}}),
			},
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: []string{"devs", "ops"},
		},
		{
			name: "a reserved group name is dropped",
			groups: []*ldap.Entry{
				group("cn=devs,dc=example", map[string][]string{"cn": {"devs"}}),
				group("cn=loa,dc=example", map[string][]string{"cn": {"krateo:loa:2"}}),
			},
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name:   "the user's ou values are not groups",
			userOU: []string{"Engineering", "Staff"},
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: []string{"devs"},
		},
		{
			name:   "no group matches: no groups, even with ou values",
			userOU: []string{"Engineering"},
			groups: []*ldap.Entry{},
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: nil,
		},
		{
			name:   "no groups",
			groups: []*ldap.Entry{},
			baseDN: "dc=example", filter: "(|(member=uid=alice,dc=example)(uniqueMember=uid=alice,dc=example))",
			attrs: []string{"cn"}, want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.username == "" {
				tc.username = "alice"
			}
			srvLDAP := &fakeLDAP{entries: 1, userDN: tc.userDN, userOU: tc.userOU, groups: tc.groups}
			gen := &fakeGenerator{}
			got := loginAs(t, "corp", 200, 200, srvLDAP, gen, false, tc.username, tc.groupSearch)
			require.Equal(t, http.StatusOK, got.code)

			require.Len(t, srvLDAP.requests, 2, "the user search, then the group search")
			if tc.userFilter != "" {
				assert.Equal(t, tc.userFilter, srvLDAP.requests[0].Filter)
			}
			assert.NotContains(t, srvLDAP.requests[0].Attributes, "ou", "ou isn't read")
			gs := srvLDAP.requests[1]
			assert.Equal(t, tc.baseDN, gs.BaseDN)
			assert.Equal(t, tc.filter, gs.Filter)
			assert.Equal(t, tc.attrs, gs.Attributes)
			_, err := ldap.CompileFilter(gs.Filter)
			assert.NoError(t, err, "the group filter is a valid LDAP filter")

			require.NotNil(t, gen.info)
			if tc.want == nil {
				assert.Empty(t, gen.info.GetGroups())
			} else {
				assert.Equal(t, tc.want, gen.info.GetGroups())
			}
		})
	}
}

// A spec.groupSearch.filter that doesn't parse, can't render, or doesn't
// render an LDAP filter is authn's misconfiguration: a 500 logged at error,
// found before authn connects to the server, so no bind is attempted.
func TestGroupSearchInvalidFilter(t *testing.T) {
	for name, filter := range map[string]string{
		"doesn't parse":         `(member={{.DN}`,
		"unknown field":         `(member={{.Email}})`,
		"not an LDAP filter":    `member={{.DN}}`,
		"unbalanced parens":     `(|(member={{.DN}})`,
		"undefined template":    `{{template "nope"}}`,
		"renders to whitespace": `{{/* nothing */}} `,
	} {
		t.Run(name, func(t *testing.T) {
			srvLDAP := &fakeLDAP{entries: 1}
			gen := &fakeGenerator{}
			gs := `{"filter":` + jsonString(t, filter) + `}`
			got := loginAs(t, "corp", 200, 200, srvLDAP, gen, false, "alice", gs)

			assert.Equal(t, http.StatusInternalServerError, got.code)
			assert.Equal(t, "LDAPConfigInvalid", got.cause)
			assert.Equal(t, "error", got.level)
			assert.Empty(t, srvLDAP.binds, "no bind is attempted")
			assert.Empty(t, srvLDAP.requests, "no search is attempted")
			assert.Zero(t, got.minted)
			assert.False(t, got.tokened)
		})
	}
}
