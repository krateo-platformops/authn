package ldap

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-ldap/ldap/v3"
)

func TestLogin(t *testing.T) {
	nfo, err := doLogin("professor", "professor", ldapConfig{
		dialURL:    "ldap://localhost:10389",
		bindDN:     "cn=admin,dc=planetexpress,dc=com",
		bindSecret: "GoodNewsEveryone",
		baseDN:     "ou=people,dc=planetexpress,dc=com",
		tls:        true,
	})
	if err != nil {
		t.Fatal(err)
	}

	spew.Dump(nfo)
}

// Example_userAuthentication shows how a typical application can verify a login attempt
// Refer to https://github.com/go-ldap/ldap/issues/93 for issues revolving around unauthenticated binds, with zero length passwords
func TestUserAuthentication(t *testing.T) {
	// The username and password we want to check
	username := "tesla"
	password := "password"

	bindDN := "cn=read-only-admin,dc=example,dc=com"
	bindSecret := "password"

	l, err := ldap.DialURL("ldap://ldap.forumsys.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	l.Debug = true

	// Reconnect with TLS
	// err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// First bind with a read only user
	err = l.Bind(bindDN, bindSecret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("===> ", "admin bind OK")

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		"dc=planetexpress,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		strings.ReplaceAll(filterTemplate, "$USERNAME", ldap.EscapeFilter(username)),
		//fmt.Sprintf("(&(objectClass=person)(uid=%s))", ldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail", "memberof", "userPassword", "ou", "o"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		log.Fatal(err)
	}

	// Rebind as the read only user for any further queries
	// err = l.Bind(bindusername, bindpassword)
	// if err != nil {
	// 	log.Fatal(err)
	// }
}

// Example_userAuthentication shows how a typical application can verify a login attempt
// Refer to https://github.com/go-ldap/ldap/issues/93 for issues revolving around unauthenticated binds, with zero length passwords
func TestUserAuthentication2(t *testing.T) {
	// The username and password we want to check
	username := "professor"
	password := "professor"

	bindDN := "cn=admin,dc=planetexpress,dc=com"
	bindSecret := "GoodNewsEveryone"

	l, err := ldap.DialURL("ldap://localhost:10389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	l.Debug = true

	// Reconnect with TLS
	// err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// First bind with a read only user
	err = l.Bind(bindDN, bindSecret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("===> ", "admin bind OK")

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		"ou=people,dc=planetexpress,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		strings.ReplaceAll(filterTemplate, "$USERNAME", ldap.EscapeFilter(username)),
		//fmt.Sprintf("(&(objectClass=person)(uid=%s))", ldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail", "memberof", "userPassword", "ou", "o"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("===> ", "user bind OK")
	// Rebind as the read only user for any further queries
	// err = l.Bind(bindusername, bindpassword)
	// if err != nil {
	// 	log.Fatal(err)
	// }
}
