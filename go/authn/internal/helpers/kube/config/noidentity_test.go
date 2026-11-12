package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// sentinel is a person whose every name carries logtest.Marker.
func sentinel(groups ...string) *userinfo.DefaultUser {
	return userAs(logtest.User, "kc", logtest.Subject, groups...)
}

// logFailure logs err, when there is one, as a login route does
// (status.LogFailure), so a check covers the error a route writes as well as
// the lines the guard or the generator writes.
func logFailure(l zerolog.Logger, err error) {
	if err != nil {
		status.LogFailure(l, status.IssueFailure("clientconfig", err)).Msg("kubeconfig creation failure")
	}
}

// statusBody is the apiserver's Status for code, naming the object as the
// apiserver does.
func statusBody(code int, reason, message string) string {
	return fmt.Sprintf(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":%q,"code":%d,"message":%q}`, reason, code, message)
}

// The name guard admits, adopts, refuses and fails without a log line, or an
// error a route logs, naming the username or the claim (Diego, 2026-11-12).
func TestNameGuardLogsNoIdentity(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Subject)
	theirs := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Marker+"-other")

	// The apiserver answers the User lookup with an error naming the User.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, statusBody(500, "InternalError", `users.basic.authn.krateo.io "`+logtest.User+`" is unreadable`))
	}))
	t.Cleanup(api.Close)
	failingSecrets := fake.NewSimpleClientset()
	failingSecrets.PrependReactor("get", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		name := a.(k8stesting.GetAction).GetName()
		return true, nil, apierrors.NewForbidden(corev1.Resource("secrets"), name, errors.New("access denied"))
	})

	for _, tc := range []struct {
		name     string
		strategy storage.Strategy
		user     *userinfo.DefaultUser
		lookup   NameLookup
		quiet    bool // an admission the guard doesn't log
	}{
		{name: "admitted: its own claim", strategy: storage.StrategyOIDC, user: sentinel(), quiet: true,
			lookup: &fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: mine})}},
		{name: "admitted: a fresh name", strategy: storage.StrategyOIDC, user: sentinel(), quiet: true, lookup: &fakeLookup{}},
		{name: "adopted: its strategy's legacy Secret", strategy: storage.StrategyOIDC, user: sentinel(),
			lookup: &fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "oidc"})}},
		{name: "adopted: a provisioned identity's legacy Secret", strategy: storage.StrategyBasic, user: sentinel(),
			lookup: &fakeLookup{secret: secretWith(nil)}},
		{name: "refused: claimed by another identity", strategy: storage.StrategyOIDC, user: sentinel(),
			lookup: &fakeLookup{secret: secretWith(map[string]string{storage.ClaimAnnotation: theirs})}},
		{name: "refused: another strategy's legacy Secret", strategy: storage.StrategyOIDC, user: sentinel(),
			lookup: &fakeLookup{secret: secretWith(map[string]string{storage.StrategyAnnotation: "ldap"})}},
		{name: "refused: provisioned", strategy: storage.StrategyOIDC, user: sentinel(), lookup: &fakeLookup{provisioned: true}},
		{name: "refused: bound", strategy: storage.StrategyOIDC, user: sentinel(), lookup: &fakeLookup{bound: true}},
		{name: "failed: no subject", strategy: storage.StrategyOIDC, user: userAs(logtest.User, "kc", ""), lookup: &fakeLookup{}},
		{name: "failed: the session Secret is unreadable", strategy: storage.StrategyOIDC, user: sentinel(),
			lookup: &clusterLookup{rc: &rest.Config{Host: api.URL}, cli: failingSecrets}},
		{name: "failed: the User is unreadable", strategy: storage.StrategyOIDC, user: sentinel(),
			lookup: &clusterLookup{rc: &rest.Config{Host: api.URL}, cli: fake.NewSimpleClientset()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs, l := logtest.Capture()
			_, err := (&nameGuard{lookup: tc.lookup, log: l}).admit(context.Background(), tc.strategy, tc.user)
			logFailure(l, err)
			if tc.quiet {
				logtest.NoIdentityIfAny(t, logs)
				return
			}
			logtest.NoIdentity(t, logs)
		})
	}
}

// secretAPI is the apiserver as the credential store sees it: creating the
// session Secret answers create (a status code), reading it answers the
// Secret with claim, and updating it answers update.
func secretAPI(t *testing.T, create, update int, claim string) *rest.Config {
	t.Helper()
	name := logtest.User + "-clientconfig"
	stored := fmt.Sprintf(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":%q,"namespace":"krateo-system","uid":"u1","resourceVersion":"1",
		"annotations":{%q:%q}}}`, name, storage.ClaimAnnotation, claim)
	answer := func(w http.ResponseWriter, code int, verb string) {
		w.WriteHeader(code)
		switch code {
		case http.StatusOK, http.StatusCreated:
			_, _ = io.WriteString(w, stored)
		case http.StatusConflict:
			if verb == "create" {
				_, _ = io.WriteString(w, statusBody(code, "AlreadyExists", `secrets "`+name+`" already exists`))
				return
			}
			_, _ = io.WriteString(w, statusBody(code, "Conflict", `Operation cannot be fulfilled on secrets "`+name+`": the object has been modified`))
		default:
			_, _ = io.WriteString(w, statusBody(code, "Forbidden", `secrets "`+name+`" is forbidden`))
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/krateo-system/secrets":
			answer(w, create, "create")
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/krateo-system/secrets/"+name:
			answer(w, http.StatusOK, "get")
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/krateo-system/secrets/"+name:
			answer(w, update, "update")
		default:
			t.Errorf("unexpected apiserver call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// Issuing a credential, from the CSR to the session Secret, logs no line, and
// fails with no error, naming the user: not its username, its groups, its CSR
// or its Secret (Diego, 2026-11-12).
func TestGenerateLogsNoIdentity(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Subject)
	theirs := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Marker+"-other")
	csrs := certv1.Resource("certificatesigningrequests")

	for _, tc := range []struct {
		name           string
		create, update int
		claim          string
		signer         func(*fake.Clientset)
	}{
		{name: "issued", create: http.StatusCreated, claim: mine},
		{name: "rewritten", create: http.StatusConflict, update: http.StatusOK, claim: mine},
		{name: "claimed by another identity at the write", create: http.StatusConflict, claim: theirs},
		{name: "the Secret write is forbidden", create: http.StatusForbidden, claim: mine},
		{name: "the Secret update conflicts", create: http.StatusConflict, update: http.StatusConflict, claim: mine},
		{name: "the CSR create fails", claim: mine, signer: func(c *fake.Clientset) {
			c.PrependReactor("create", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
				csr := a.(k8stesting.CreateAction).GetObject().(*certv1.CertificateSigningRequest)
				return true, nil, apierrors.NewAlreadyExists(csrs, csr.GenerateName+"00001")
			})
		}},
		{name: "the CSR approval is forbidden", claim: mine, signer: func(c *fake.Clientset) {
			c.PrependReactor("update", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
				csr := a.(k8stesting.UpdateAction).GetObject().(*certv1.CertificateSigningRequest)
				return true, nil, apierrors.NewForbidden(csrs, csr.Name, errors.New("approval denied"))
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, _ := fakeSigner(t)
			if tc.signer != nil {
				tc.signer(cli)
			}
			logs, l := logtest.Capture()
			rc := secretAPI(t, tc.create, tc.update, tc.claim)
			gen := NewGenerator(rc, CAData("ca"), KubernetesURL("https://k8s.example"), CertDuration(time.Hour),
				Log(l), Lookup(&fakeLookup{}), Storage(storage.Default(rc))).(*kubeconfigGenerator)
			gen.csrClient = cli

			// The identity source asserted authn's reserved group: it is
			// dropped, and the warning says so without naming anyone.
			user := userinfo.NewDefaultUser(logtest.User, "1", []string{logtest.Marker + "-group", "krateo:loa:2"}, nil)
			user.Subject = userinfo.Subject{Issuer: "kc", ID: logtest.Subject}
			_, err := gen.Generate(storage.StrategyOIDC, user)
			logFailure(l, err)

			require.True(t, strings.Contains(logs.String(), "dropped reserved groups"), logs.String())
			logtest.NoIdentity(t, logs)
		})
	}
}
