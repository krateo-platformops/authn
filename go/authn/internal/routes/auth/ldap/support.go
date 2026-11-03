package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
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
)

type ldapConfig struct {
	dialURL    string
	bindDN     string
	bindSecret string
	baseDN     string
	filter     string
	tls        bool
}

// getConfig reads the LDAPConfig name and its bind Secret. An LDAPConfig that
// doesn't exist is the caller's mistake (404); one authn can't read, or whose
// bind Secret it can't read, is authn's failure (500).
func getConfig(rc *rest.Config, name string, username string) (ldapConfig, error) {
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
		dialURL: cfg.Spec.DialURL,
		baseDN:  cfg.Spec.BaseDN,
		bindDN:  ptr.Deref(cfg.Spec.BindDN, ""),
		filter:  strings.ReplaceAll(filterTemplate, "$USERNAME", username),
		tls:     ptr.Deref(cfg.Spec.TLS, false),
	}

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
		return nil, status.Failed(CauseLDAPUnavailable, err)
	}
	defer l.Close()

	if cfg.tls {
		// Reconnect with TLS
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, status.Failed(CauseLDAPUnavailable, err)
		}
	}

	// First bind with the admin user
	err = l.Bind(cfg.bindDN, cfg.bindSecret)
	if err != nil {
		return nil, serverFailure(CauseLDAPBindFailed, err)
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		cfg.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		strings.ReplaceAll(filterTemplate, "$USERNAME", ldap.EscapeFilter(username)),
		//fmt.Sprintf("(&(objectClass=person)(uid=%s))", ldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail", "memberof", "userPassword", "ou", "o"},
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
			return nil, invalidCredentials(err)
		}
		return nil, serverFailure(CauseLDAPBindFailed, err)
	}

	// Now perform a search for groups that the user belongs to
	groupFilter := fmt.Sprintf("(uniquemember=uid=%s,dc=example,dc=com)", ldap.EscapeFilter(username))
	groupSearchRequest := ldap.NewSearchRequest(
		cfg.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{"cn"},
		nil,
	)

	groupSR, err := l.Search(groupSearchRequest)
	if err != nil {
		return nil, serverFailure(CauseLDAPSearchFailed, err)
	}

	groups := []string{}
	for _, entry := range groupSR.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	nfo := ldapEntryToUserInfo(user)
	if len(nfo.GetGroups()) == 0 {
		nfo.SetGroups(groups)
	}

	return nfo, nil
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
		return status.Failed(CauseLDAPUnavailable, err)
	}
	return status.Failed(cause, err)
}

func ldapEntryToUserInfo(entry *ldap.Entry) userinfo.Info {
	exts := userinfo.Extensions{}
	exts.Add("name", entry.GetAttributeValue("cn"))
	exts.Add("email", entry.GetAttributeValue("mail"))
	exts.Add("avatarUrl",
		fmt.Sprintf("https://ui-avatars.com/api/?name=%s&size=128&bold=true&background=random&rounded=true", entry.GetAttributeValue("cn")))

	uid, _ := shortid.Generate()
	nfo := userinfo.NewDefaultUser(
		entry.GetAttributeValue("uid"), uid,
		entry.GetAttributeValues("ou"), exts)

	return nfo
}

func execUserDnTemplate(text string, vals map[string]string) (string, error) {
	tmpl, err := template.New("userDN").Parse(text)
	if err != nil {
		return "", err
	}

	buf := bytes.Buffer{}
	err = tmpl.Execute(&buf, vals)
	return buf.String(), err
}
