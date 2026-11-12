package config

import (
	"context"
	"encoding/json"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
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
	// Nor a User or mapping of that name: the guard goes on to the bindings.
	absent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, statusBody(404, "NotFound", `users.basic.authn.krateo.io "`+logtest.User+`" not found`))
	}))
	t.Cleanup(absent.Close)
	failingBindings := fake.NewSimpleClientset()
	failingBindings.PrependReactor("list", "clusterrolebindings", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(rbacv1.Resource("clusterrolebindings"), "", errors.New("access denied"))
	})
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
		{name: "failed: the bindings can't be listed", strategy: storage.StrategyOIDC, user: sentinel(),
			lookup: &clusterLookup{rc: &rest.Config{Host: absent.URL}, cli: failingBindings}},
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

// secretReplies are the apiserver's answers to the credential store: to the
// Secret's create, its read, and its update, as status codes; claim is the
// claim the stored Secret carries.
type secretReplies struct {
	create, get, update int
	claim               string
}

// secretAPI is the apiserver as the credential store sees it, for the Secret
// name. Its errors name the Secret, as the apiserver's do.
func secretAPI(t *testing.T, name string, r secretReplies) *rest.Config {
	t.Helper()
	if r.get == 0 {
		r.get = http.StatusOK
	}
	stored := fmt.Sprintf(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":%q,"namespace":"krateo-system","uid":"u1","resourceVersion":"1",
		"annotations":{%q:%q}}}`, name, storage.ClaimAnnotation, r.claim)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/api/v1/namespaces/krateo-system/secrets":
			answer(w, r.create, "create")
		case req.Method == http.MethodGet && req.URL.Path == "/api/v1/namespaces/krateo-system/secrets/"+name:
			answer(w, r.get, "get")
		case req.Method == http.MethodPut && req.URL.Path == "/api/v1/namespaces/krateo-system/secrets/"+name:
			answer(w, r.update, "update")
		default:
			t.Errorf("unexpected apiserver call: %s %s", req.Method, req.URL.Path)
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

var csrGR = certv1.Resource("certificatesigningrequests")

// Ways the CSR API misbehaves, each set on a fakeSigner. Every error names
// the CSR, as the apiserver's and client-go's do.
var (
	csrCreateFails = func(c *fake.Clientset) {
		c.PrependReactor("create", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
			csr := a.(k8stesting.CreateAction).GetObject().(*certv1.CertificateSigningRequest)
			return true, nil, apierrors.NewAlreadyExists(csrGR, csr.GenerateName+"00001")
		})
	}
	csrApprovalForbidden = func(c *fake.Clientset) {
		c.PrependReactor("update", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
			csr := a.(k8stesting.UpdateAction).GetObject().(*certv1.CertificateSigningRequest)
			return true, nil, apierrors.NewForbidden(csrGR, csr.Name, errors.New("approval denied"))
		})
	}
	// An approver denies it, with a message that names the user.
	csrDenied = func(c *fake.Clientset) {
		c.PrependReactor("update", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
			csr := a.(k8stesting.UpdateAction).GetObject().(*certv1.CertificateSigningRequest).DeepCopy()
			csr.Status.Conditions = []certv1.CertificateSigningRequestCondition{{Type: certv1.CertificateDenied,
				Status: corev1.ConditionTrue, Reason: "Policy", Message: csr.Name + " may not sign in"}}
			return true, csr, c.Tracker().Update(certv1.SchemeGroupVersion.WithResource("certificatesigningrequests"), csr, "")
		})
	}
	// Someone deletes it while authn waits for its certificate.
	csrDeletedWhileWaiting = func(c *fake.Clientset) {
		gvr := certv1.SchemeGroupVersion.WithResource("certificatesigningrequests")
		c.PrependReactor("update", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
			return true, a.(k8stesting.UpdateAction).GetObject(), nil // approved, never signed
		})
		c.PrependWatchReactor("certificatesigningrequests", func(a k8stesting.Action) (bool, watch.Interface, error) {
			name, _ := a.(k8stesting.WatchAction).GetWatchRestrictions().Fields.RequiresExactMatch("metadata.name")
			w, err := c.Tracker().Watch(gvr, "")
			if err != nil {
				return true, nil, err
			}
			go func() { _ = c.Tracker().Delete(gvr, "", name) }()
			return true, w, nil
		})
	}
	csrDeleteFails = func(c *fake.Clientset) {
		c.PrependReactor("delete", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(csrGR, a.(k8stesting.DeleteAction).GetName(), errors.New("no delete"))
		})
	}
	// The signer grants 10 minutes of the hour asked for.
	signerCapped = func(c *fake.Clientset) {
		c.PrependReactor("update", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() == "approval" {
				short := int32(600)
				a.(k8stesting.UpdateAction).GetObject().(*certv1.CertificateSigningRequest).Spec.ExpirationSeconds = &short
			}
			return false, nil, nil
		})
	}
)

// generator is a generator for tests: a fake signer changed by signer, the
// store answering r for the Secret name, no cluster lookup, logging to l.
func generator(t *testing.T, name string, r secretReplies, signer func(*fake.Clientset), l zerolog.Logger) *kubeconfigGenerator {
	t.Helper()
	cli, _ := fakeSigner(t)
	if signer != nil {
		signer(cli)
	}
	rc := secretAPI(t, name, r)
	gen := NewGenerator(rc, CAData("ca"), KubernetesURL("https://k8s.example"), CertDuration(time.Hour),
		Log(l), Lookup(&fakeLookup{}), Storage(storage.Default(rc))).(*kubeconfigGenerator)
	gen.csrClient = cli
	return gen
}

// sentinelUser is username with a sentinel group and an IdP's copy of
// authn's reserved group, which is dropped with a warning naming no one.
func sentinelUser(username string) *userinfo.DefaultUser {
	user := userinfo.NewDefaultUser(username, "1", []string{logtest.Marker + "-group", "krateo:loa:2"}, nil)
	user.Subject = userinfo.Subject{Issuer: "kc", ID: logtest.Subject}
	return user
}

// Issuing a credential, from the CSR to the session Secret, logs no line, and
// fails with no error, naming the user: not its username, its groups, its CSR
// or its Secret (Diego, 2026-11-12). A username longer than the apiserver
// keeps of a CSR's generateName is no exception.
func TestGenerateLogsNoIdentity(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Subject)
	theirs := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Marker+"-other")

	for _, username := range []string{logtest.User, logtest.LongUser} {
		for _, tc := range []struct {
			name    string
			replies secretReplies
			signer  func(*fake.Clientset)
			msg     string // a line the case must log
		}{
			{name: "issued", replies: secretReplies{create: http.StatusCreated, claim: mine}, msg: "certificate acquired"},
			{name: "rewritten", replies: secretReplies{create: http.StatusConflict, update: http.StatusOK, claim: mine}},
			{name: "claimed by another identity at the write", replies: secretReplies{create: http.StatusConflict, claim: theirs},
				msg: "username refused"},
			{name: "the claimed Secret can't be read", replies: secretReplies{create: http.StatusConflict, get: http.StatusForbidden, claim: mine},
				msg: "kubeconfig creation failure"},
			{name: "the Secret write is forbidden", replies: secretReplies{create: http.StatusForbidden, claim: mine}, msg: "kubeconfig creation failure"},
			{name: "the Secret update conflicts", replies: secretReplies{create: http.StatusConflict, update: http.StatusConflict, claim: mine},
				msg: "kubeconfig creation failure"},
			{name: "the CSR create fails", signer: csrCreateFails, msg: "kubeconfig creation failure"},
			{name: "the CSR approval is forbidden", signer: csrApprovalForbidden, msg: "kubeconfig creation failure"},
			{name: "the CSR is denied", signer: csrDenied, msg: "the CSR was denied"},
			{name: "the CSR is deleted while authn waits", signer: csrDeletedWhileWaiting, msg: "the CSR was deleted"},
			{name: "the used CSR can't be deleted", replies: secretReplies{create: http.StatusCreated, claim: mine}, signer: csrDeleteFails,
				msg: "deleting used certificate signing request"},
			{name: "the signer grants less", replies: secretReplies{create: http.StatusCreated, claim: mine}, signer: signerCapped,
				msg: "materially shorter"},
		} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, len(username)), func(t *testing.T) {
				logs, l := logtest.Capture()
				gen := generator(t, storage.ClientConfigSecretName(username), tc.replies, tc.signer, l)
				_, err := gen.Generate(storage.StrategyOIDC, sentinelUser(username))
				logFailure(l, err)

				require.Contains(t, logs.String(), "dropped reserved groups")
				require.Contains(t, logs.String(), tc.msg)
				logtest.NoIdentity(t, logs)
			})
		}
	}
}

// A step-up credential is issued, or refused, the same way.
func TestGenerateStepUpLogsNoIdentity(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Subject)
	for _, username := range []string{logtest.User, logtest.LongUser} {
		t.Run(fmt.Sprint(len(username)), func(t *testing.T) {
			logs, l := logtest.Capture()
			gen := generator(t, storage.StepUpSecretName(username), secretReplies{create: http.StatusCreated, claim: mine}, nil, l)
			_, err := gen.GenerateStepUp(storage.StrategyOIDC, userinfo.NewStepUpUser(sentinelUser(username), 2), 15*time.Minute)
			require.NoError(t, err)

			// No krateo:loa: group: not a step-up identity, refused.
			plain := userinfo.NewDefaultUser(username, "1", []string{logtest.Marker + "-group"}, nil)
			plain.Subject = userinfo.Subject{Issuer: "kc", ID: logtest.Subject}
			_, err = gen.GenerateStepUp(storage.StrategyOIDC, plain, 15*time.Minute)
			require.Error(t, err)
			logFailure(l, err)

			require.Contains(t, logs.String(), "certificate acquired")
			require.Contains(t, logs.String(), "must carry a krateo:loa: group")
			logtest.NoIdentity(t, logs)
		})
	}
}

// With Logger, an issuance logs with the request's logger, so its lines carry
// the request's session.id and join the request's audit record; the
// generator's own logger is left silent.
func TestIssuanceLogsWithTheRequestsLogger(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	mine := storage.EncodeClaim(storage.StrategyOIDC, "kc", logtest.Subject)
	own, ownLog := logtest.Capture()
	reqBuf, reqLog := logtest.Capture()
	reqLog = reqLog.With().Str("session.id", "s-1").Logger()

	gen := generator(t, storage.ClientConfigSecretName(logtest.User), secretReplies{create: http.StatusCreated, claim: mine}, signerCapped, ownLog)
	_, err := gen.Generate(storage.StrategyOIDC, sentinelUser(logtest.User), Logger(reqLog))
	require.NoError(t, err)
	gen.lookup = &fakeLookup{bound: true} // a refusal, from the name guard
	_, err = gen.Generate(storage.StrategyOIDC, sentinelUser(logtest.User), Logger(reqLog))
	require.Error(t, err)

	assert.Empty(t, own.String(), "nothing on the generator's own logger")
	lines := strings.Split(strings.TrimSpace(reqBuf.String()), "\n")
	for _, msg := range []string{"dropped reserved groups", "created certificate signing request", "materially shorter", "username refused"} {
		assert.Contains(t, reqBuf.String(), msg)
	}
	for _, line := range lines {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m), line)
		assert.Equal(t, "s-1", m["session.id"], line)
	}
	logtest.NoIdentity(t, reqBuf)
}

// A group refusal names the rule, never the group: a group name an identity
// source asserted can be the person's own (Diego, 2026-11-12).
func TestGroupRefusalsLogNoIdentity(t *testing.T) {
	t.Setenv(util.NamespaceEnvVar, "krateo-system")
	for name, group := range map[string]string{
		"system: group":       "system:" + logtest.Marker + "-group",
		"krateo: group":       "krateo:" + logtest.Marker + "-group",
		"a newline":           logtest.Marker + "\ngroup",
		"authn's step-up one": userinfo.StepUpGroup(2) + "-" + logtest.Marker,
	} {
		t.Run(name, func(t *testing.T) {
			logs, l := logtest.Capture()
			gen := generator(t, storage.ClientConfigSecretName(logtest.User), secretReplies{create: http.StatusCreated}, nil, l)
			user := &userinfo.DefaultUser{Name: logtest.User, ID: "1", Groups: []string{group},
				Subject: userinfo.Subject{Issuer: "kc", ID: logtest.Subject}}
			_, err := gen.Generate(storage.StrategyOIDC, user)
			require.Error(t, err)
			logFailure(l, err)
			logtest.NoIdentity(t, logs)
		})
	}
}
