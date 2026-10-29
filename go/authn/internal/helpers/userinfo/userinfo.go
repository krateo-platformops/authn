package userinfo

import (
	"fmt"
	"strings"
)

// ReservedGroupPrefix marks groups that only authn grants, never an identity
// source. krateo:loa:<n> records the assurance level of a step-up login
// (#49), and admission policies trust it. A user must not be able to assert it
// through an IdP groups claim, a RESTAction, a basic User or a ServiceAccount
// mapping, so every Info built here drops it.
const ReservedGroupPrefix = "krateo:loa:"

// StepUpGroup is the reserved group recording a step-up login at level, e.g.
// krateo:loa:2.
func StepUpGroup(level int) string {
	return fmt.Sprintf("%s%d", ReservedGroupPrefix, level)
}

// NewStepUpUser returns a copy of base that also carries StepUpGroup(level).
// It is the only way an Info gets a reserved group. Call it only after the
// login has proven that assurance level.
func NewStepUpUser(base Info, level int) *DefaultUser {
	groups := append(append([]string{}, base.GetGroups()...), StepUpGroup(level))
	return &DefaultUser{
		Name:       base.GetUserName(),
		ID:         base.GetID(),
		Groups:     groups,
		Extensions: base.GetExtensions(),
		dropped:    base.DroppedGroups(),
	}
}

// IsReserved reports whether group is one only authn may grant.
func IsReserved(group string) bool {
	return strings.HasPrefix(group, ReservedGroupPrefix)
}

// withoutReserved splits groups into those an identity source may assert and
// the reserved ones it may not.
func withoutReserved(groups []string) (kept, dropped []string) {
	for _, g := range groups {
		if IsReserved(g) {
			dropped = append(dropped, g)
			continue
		}
		kept = append(kept, g)
	}
	return kept, dropped
}

// Info describes a user that has been authenticated to the system.
type Info interface {
	// GetUserName returns the name that uniquely identifies this user among all
	// other active users.
	GetUserName() string
	// SetUserName set the name that uniquely identifies this user among all
	// other active users.
	SetUserName(string)
	// GetID returns a unique value identify a particular user.
	GetID() string
	// SetID set a unique value identify a particular user.
	SetID(string)
	// GetGroups returns the names of the groups the user is a member of
	GetGroups() []string
	// SetGroups set the names of the groups the user is a member of.
	// Reserved groups (see ReservedGroupPrefix) are dropped.
	SetGroups(groups []string)
	// DroppedGroups returns the reserved groups an identity source asserted
	// and that were dropped, so the issuer can report them.
	DroppedGroups() []string
	// Extensions can contain any additional information.
	GetExtensions() Extensions
	// SetExtensions to contain additional information.
	SetExtensions(exts Extensions)
}

// DefaultUser implement Info interface and provides a simple user information.
type DefaultUser struct {
	Name       string
	ID         string
	Groups     []string
	Extensions Extensions

	dropped []string
}

// GetUserName returns the name that uniquely identifies this user among all
// other active users.
func (d *DefaultUser) GetUserName() string {
	return d.Name
}

// SetUserName set the name that uniquely identifies this user among all
// other active users.
func (d *DefaultUser) SetUserName(name string) {
	d.Name = name
}

// GetID returns a unique value identify a particular user
func (d *DefaultUser) GetID() string {
	return d.ID
}

// SetID set a unique value identify a particular user.
func (d *DefaultUser) SetID(id string) {
	d.ID = id
}

// GetGroups returns the names of the groups the user is a member of
func (d *DefaultUser) GetGroups() []string {
	return d.Groups
}

// SetGroups set the names of the groups the user is a member of. Reserved
// groups are dropped and remembered (see DroppedGroups).
func (d *DefaultUser) SetGroups(groups []string) {
	d.Groups, d.dropped = withoutReserved(groups)
}

// DroppedGroups returns the reserved groups dropped from what the identity
// source asserted.
func (d *DefaultUser) DroppedGroups() []string {
	return d.dropped
}

// GetExtensions return additional information.
func (d *DefaultUser) GetExtensions() Extensions {
	if d.Extensions == nil {
		d.Extensions = Extensions{}
	}
	return d.Extensions
}

// SetExtensions to contain additional information.
func (d *DefaultUser) SetExtensions(exts Extensions) {
	d.Extensions = exts
}

// NewDefaultUser return new default user. Reserved groups are dropped (see
// ReservedGroupPrefix): groups come from identity sources, which may not
// grant them.
func NewDefaultUser(name, id string, groups []string, extensions Extensions) *DefaultUser {
	d := &DefaultUser{
		Name:       name,
		ID:         id,
		Extensions: extensions,
	}
	d.SetGroups(groups)
	return d
}
