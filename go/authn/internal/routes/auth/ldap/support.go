package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/shortid"
	"github.com/krateo-platformops/authn/internal/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

const (
	filterTemplate = "(|(cn=$USERNAME)(uid=$USERNAME)(userPrincipalName=$USERNAME)(mail=$USERNAME))"

	// The group search defaults (spec.groupSearch).
	defaultGroupFilter        = "(|(member={{.DN}})(uniqueMember={{.DN}}))"
	defaultGroupNameAttribute = "cn"
)

type ldapConfig struct {
	// name is the LDAPConfig's name, the issuer of the subjects it
	// authenticates (userinfo.Subject).
	name       string
	dialURL    string
	bindDN     string
	bindSecret string
	baseDN     string
	tls        bool

	groupBaseDN   string
	groupFilter   *template.Template
	groupNameAttr string
}

// groupFilterVars are the values spec.groupSearch.filter is rendered with.
// Each is escaped for an LDAP filter (ldap.EscapeFilter) before it is
// substituted, so neither the username nor the DN can inject filter syntax.
type groupFilterVars struct {
	DN       string // the DN the user bound as
	Username string // the login name
}

// parseGroupFilter parses a spec.groupSearch.filter template and checks it
// renders a valid LDAP filter, so a bad one fails before any bind.
func parseGroupFilter(text string) (*template.Template, error) {
	tmpl, err := template.New("groupSearch.filter").Parse(text)
	if err != nil {
		return nil, err
	}
	sample, err := renderGroupFilter(tmpl, "uid=sample,dc=example", "sample")
	if err != nil {
		return nil, err
	}
	if _, err := ldap.CompileFilter(sample); err != nil {
		return nil, fmt.Errorf("it renders %q, not an LDAP filter: %w", sample, err)
	}
	return tmpl, nil
}

// renderGroupFilter renders the group filter for the user who bound as dn
// with the login name username, escaping both.
func renderGroupFilter(tmpl *template.Template, dn, username string) (string, error) {
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, groupFilterVars{
		DN:       ldap.EscapeFilter(dn),
		Username: ldap.EscapeFilter(username),
	})
	return buf.String(), err
}

// getConfig reads the LDAPConfig name and its bind Secret. An LDAPConfig that
// doesn't exist is the caller's mistake (404); one authn can't read, or whose
// bind Secret it can't read, is authn's failure (500), and so is one whose
// spec.groupSearch.filter is unusable (LDAPConfigInvalid), found here, before
// any connection to the server.
func getConfig(rc *rest.Config, name string) (ldapConfig, error) {
	if len(rest.IsValidPathSegmentName(name)) > 0 {
		// No LDAPConfig can have this name; looking it up would fail client-side.
		return ldapConfig{}, status.CauseError{Code: http.StatusNotFound, Cause: CauseLDAPConfigNotFound,
			Err: fmt.Errorf("LDAPConfig %q not found", name)}
	}
	cfg, err := resolvers.LDAPConfigGet(rc, name)
	switch {
	case apierrors.IsNotFound(err):
		return ldapConfig{}, status.CauseError{Code: http.StatusNotFound, Cause: CauseLDAPConfigNotFound,
			Err: fmt.Errorf("LDAPConfig %q not found", name)}
	case err != nil:
		return ldapConfig{}, status.Failed(CauseLDAPConfigLookupFailed, fmt.Errorf("unable to resolve LDAP configuration: %w", err))
	}

	res := ldapConfig{
		name:    name,
		dialURL: cfg.Spec.DialURL,
		baseDN:  cfg.Spec.BaseDN,
		bindDN:  ptr.Deref(cfg.Spec.BindDN, ""),
		tls:     ptr.Deref(cfg.Spec.TLS, false),

		groupBaseDN:   cfg.Spec.BaseDN,
		groupNameAttr: defaultGroupNameAttribute,
	}

	groupFilter := defaultGroupFilter
	if gs := cfg.Spec.GroupSearch; gs != nil {
		if gs.BaseDN != "" {
			res.groupBaseDN = gs.BaseDN
		}
		if gs.Filter != "" {
			groupFilter = gs.Filter
		}
		if gs.NameAttribute != "" {
			res.groupNameAttr = gs.NameAttribute
		}
	}
	tmpl, err := parseGroupFilter(groupFilter)
	if err != nil {
		return res, status.Failed(CauseLDAPConfigInvalid,
			fmt.Errorf("LDAPConfig %q: invalid spec.groupSearch.filter: %w", name, err))
	}
	res.groupFilter = tmpl

	if ref := cfg.Spec.BindSecret; ref != nil {
		sec, err := secrets.Get(context.Background(), rc, ref)
		if err != nil {
			return res, status.Failed(CauseLDAPConfigLookupFailed, fmt.Errorf("reading the bind secret: %w", err))
		}
		if val, ok := sec.Data[ref.Key]; ok {
			res.bindSecret = string(val)
		}
	}

	return res, nil
}

// dial connects to the LDAP server; tests replace it with a fake.
var dial = func(url string) (ldap.Client, error) { return ldap.DialURL(url) }

// doLogin authenticates username against the LDAP server. Every error it
// returns is a status.CauseError: the caller's refusal (the user is unknown,
// ambiguous, or its bind is refused) or authn's failure (the server can't be
// reached, or refuses authn's own bind or search). An unknown user and a
// refused bind are the same InvalidCredentials body, so a caller can't probe
// which users exist; the real reason only reaches the log.
func doLogin(username, password string, cfg ldapConfig) (userinfo.Info, error) {
	l, err := dial(cfg.dialURL)
	if err != nil {
		return nil, status.Failed(CauseLDAPUnavailable, ldapResult(err))
	}
	defer l.Close()

	if cfg.tls {
		// Reconnect with TLS
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, status.Failed(CauseLDAPUnavailable, ldapResult(err))
		}
	}

	// First bind with the admin user
	err = l.Bind(cfg.bindDN, cfg.bindSecret)
	if err != nil {
		return nil, serverFailure(CauseLDAPBindFailed, err)
	}

	// Search for the given username. Ask only for the attributes
	// ldapEntryToUserInfo reads: never userPassword, whose hash authn has no
	// use for.
	searchRequest := ldap.NewSearchRequest(
		cfg.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		strings.ReplaceAll(filterTemplate, "$USERNAME", ldap.EscapeFilter(username)),
		//fmt.Sprintf("(&(objectClass=person)(uid=%s))", ldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, serverFailure(CauseLDAPSearchFailed, err)
	}

	if len(sr.Entries) == 0 {
		return nil, invalidCredentials(errNotFound)
	}

	if len(sr.Entries) > 1 {
		return nil, status.CauseError{Code: http.StatusMultipleChoices, Cause: CauseAmbiguousUser, Err: errTooManyEntries}
	}

	user := sr.Entries[0]
	// Bind as the user to verify their password
	err = l.Bind(user.DN, password)
	if err != nil {
		if refusesUser(err) {
			return nil, invalidCredentials(ldapResult(err))
		}
		return nil, serverFailure(CauseLDAPBindFailed, err)
	}

	// Now search for the groups the user belongs to (spec.groupSearch).
	groupFilter, err := renderGroupFilter(cfg.groupFilter, user.DN, username)
	if err != nil {
		return nil, status.Failed(CauseLDAPConfigInvalid, fmt.Errorf("rendering spec.groupSearch.filter: %w", err))
	}
	groupSearchRequest := ldap.NewSearchRequest(
		cfg.groupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{cfg.groupNameAttr},
		nil,
	)

	groupSR, err := l.Search(groupSearchRequest)
	if err != nil {
		return nil, serverFailure(CauseLDAPSearchFailed, err)
	}

	// The user's groups are exactly what the group search found (#72): the
	// user entry's own attributes (e.g. ou) are not groups.
	return ldapEntryToUserInfo(user, groupNames(groupSR.Entries, cfg.groupNameAttr), cfg.name), nil
}

// groupNames names each group entry by its nameAttr value, in order and
// without duplicates. Attribute names are case-insensitive. An entry without
// the attribute is skipped, not named "".
func groupNames(entries []*ldap.Entry, nameAttr string) []string {
	groups := []string{}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.GetEqualFoldAttributeValue(nameAttr)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		groups = append(groups, name)
	}
	return groups
}

// invalidCredentials refuses the caller with the one InvalidCredentials body;
// reason goes to the log only.
func invalidCredentials(reason error) error {
	return status.RefusedPrivately(CauseInvalidCredentials, errInvalidCredentials, reason)
}

// refusesUser reports whether err is the server's (or the client's) verdict on
// the user's own credentials: wrong password, an authentication the server won't
// accept for this user (e.g. a disabled account), or an empty password.
func refusesUser(err error) bool {
	for _, code := range []uint16{
		ldap.LDAPResultInvalidCredentials,
		ldap.LDAPResultInappropriateAuthentication,
		ldap.LDAPResultUnwillingToPerform,
		ldap.ErrorEmptyPassword,
	} {
		if ldap.IsErrorWithCode(err, code) {
			return true
		}
	}
	return false
}

// serverFailure is authn's failure talking to the LDAP server: a lost
// connection is LDAPUnavailable, any other error is cause.
func serverFailure(cause status.CauseType, err error) error {
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return status.Failed(CauseLDAPUnavailable, ldapResult(err))
	}
	return status.Failed(cause, ldapResult(err))
}

// ldapResult describes err by its LDAP result code alone, and a lost
// connection by its kind: a server's diagnostic message can carry the DN or
// the login name, and the error is logged as well as answered. err stays
// reachable to errors.As (ldap.IsErrorWithCode).
func ldapResult(err error) error {
	var le *ldap.Error
	if !errors.As(err, &le) {
		return kerr.Described("the LDAP request failed", err)
	}
	text := fmt.Sprintf("LDAP result %d (%s)", le.ResultCode, ldap.LDAPResultCodeMap[le.ResultCode])
	if le.ResultCode == ldap.ErrorNetwork && le.Err != nil {
		text += ": " + kerr.Transport(le.Err)
	}
	return kerr.Described(text, err)
}

// ldapEntryToUserInfo is the identity of the user entry, with groups (from the
// group search). NewDefaultUser drops reserved groups (krateo:loa:). Its
// subject is the entry's DN, issued by the LDAPConfig named config.
func ldapEntryToUserInfo(entry *ldap.Entry, groups []string, config string) userinfo.Info {
	exts := userinfo.Extensions{}
	exts.Add("name", entry.GetAttributeValue("cn"))
	exts.Add("email", entry.GetAttributeValue("mail"))
	exts.Add("avatarUrl",
		fmt.Sprintf("https://ui-avatars.com/api/?name=%s&size=128&bold=true&background=random&rounded=true", entry.GetAttributeValue("cn")))

	uid, _ := shortid.Generate()
	nfo := userinfo.NewDefaultUser(
		entry.GetAttributeValue("uid"), uid,
		groups, exts)
	nfo.Subject = userinfo.Subject{Issuer: config, ID: entry.DN}

	return nfo
}
