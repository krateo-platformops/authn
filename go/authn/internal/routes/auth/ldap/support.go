package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/shortid"
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

func getConfig(rc *rest.Config, name string, username string) (ldapConfig, error) {
	cfg, err := resolvers.LDAPConfigGet(rc, name)
	if err != nil {
		return ldapConfig{}, fmt.Errorf("unable to resolve LDAP configuration")
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
			return res, err
		}
		if val, ok := sec.Data[ref.Key]; ok {
			res.bindSecret = string(val)
		}
	}

	return res, nil
}

func doLogin(username, password string, cfg ldapConfig) (userinfo.Info, error) {
	l, err := ldap.DialURL(cfg.dialURL)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	//l.Debug = true

	if cfg.tls {
		// Reconnect with TLS
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	}

	// First bind with the admin user
	err = l.Bind(cfg.bindDN, cfg.bindSecret)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return nil, errNotFound
	}

	if len(sr.Entries) > 1 {
		return nil, errTooManyEntries
	}

	user := sr.Entries[0]
	// Bind as the user to verify their password
	err = l.Bind(user.DN, password)
	if err != nil {
		return nil, err
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
		return nil, err
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
