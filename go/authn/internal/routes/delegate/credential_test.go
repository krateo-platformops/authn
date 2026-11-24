package delegate

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/auditlog/auditlogtest"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/routes/jwks"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// withGenerator is the route, served as main serves it, with an audit
// Recorder, the lookup and gen.
func (k keys) withGenerator(t *testing.T, rc *rest.Config, lookup kubeconfig.NameLookup, gen kubeconfig.Generator) (http.Handler, *audittest.Recorder) {
	t.Helper()
	rec, records := auditlogtest.New(t)
	return auditlog.Middleware(Route(rc, Options{
		PrivateKey: k.current, KeyID: "current",
		PreviousKeys: []jwks.Key{{KID: "previous", Pub: &k.previous.PublicKey}},
		Audit:        rec, Lookup: lookup, Generator: gen,
	}).Handler()), records
}

// authn#167: an exchange of alice's authn token issues, with the token, a
// credential for exactly the token's username and groups, through the actor:
// her step-up group is in neither. It records alice's session identity, and
// its write is its own record.
func TestDelegatedTokenAndCredentialCarryTheSameGroups(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	gen := &fakeGenerator{}
	h, records := k.withGenerator(t, rc, everyoneSignedIn{}, gen)

	out, nfo := issued(t, k, exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil))))
	call, n := gen.only()
	require.Equal(t, 1, n, "one credential per exchange")
	assert.Equal(t, "alice", call.username)
	assert.Equal(t, "kagent", call.actor, "the token's outermost actor")
	assert.Equal(t, []string{"devs"}, call.groups)
	assert.Equal(t, nfo.Groups, call.groups, "the token's groups are the credential's")
	assert.Equal(t, storage.StrategyOIDC, call.strategy, "alice's session strategy")
	assert.Equal(t, sessionClaim("alice"), call.claim, "alice's session claim")
	assert.LessOrEqual(t, call.ttl, DefaultTTL)
	assert.LessOrEqual(t, time.Duration(out.ExpiresIn)*time.Second, call.ttl)

	r := auditlogtest.OnlyAction(t, records, auditlog.ActionDelegateCredential)
	assert.Equal(t, audit.OutcomeSuccess, auditlogtest.String(r, "krateo.audit.outcome"))
	assert.Equal(t, "alice", auditlogtest.String(r, "user.name"))
	assert.Equal(t, "secrets", auditlogtest.String(r, "krateo.audit.object_ref.resource"))
	assert.Equal(t, storage.DelegatedSecretName("alice", "kagent", []string{"devs"}), auditlogtest.String(r, "krateo.audit.object_ref.name"))
	assert.Equal(t, audit.OutcomeSuccess,
		auditlogtest.String(auditlogtest.OnlyAction(t, records, auditlog.ActionDelegate), "krateo.audit.outcome"))
}

// An identity provider's token: the credential records the identity the
// claim-first rule vouched for, and carries the provider token's groups.
func TestDelegatedCredentialOfAnIdentityProvidersToken(t *testing.T) {
	k, kc := newKeys(t), newRealm(t)
	rc := idpAPIServer(t, kc, idpDelegation, []string{"tenants", "platform-admins"})
	gen := &fakeGenerator{}
	h, _ := k.withGenerator(t, rc, secrets{"alice": claimed(kc.claimOf("uid-alice"))}, gen)

	_, nfo := issued(t, k, exchange(h, "sa", idpForm(kc.accessToken(t, kc.key, jwt.SigningMethodRS256, nil))))
	call, n := gen.only()
	require.Equal(t, 1, n)
	assert.Equal(t, storage.StrategyOIDC, call.strategy)
	assert.Equal(t, kc.claimOf("uid-alice"), call.claim, "the vouched-for claim")
	assert.Equal(t, nfo.Groups, call.groups)
	assert.Equal(t, "kagent", call.actor)
}

// The token never outlives its credential: a signer that grants less than
// was asked shortens the token too.
func TestDelegatedTokenNeverOutlivesItsCredential(t *testing.T) {
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	gen := &fakeGenerator{grant: 5 * time.Minute}
	h, _ := k.withGenerator(t, rc, everyoneSignedIn{}, gen)

	out, _ := issued(t, k, exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil))))
	assert.LessOrEqual(t, out.ExpiresIn, int64(300))
	assert.Greater(t, out.ExpiresIn, int64(240))
}

// No credential, no token: a credential that fails is a failed exchange,
// and one refused is a refused exchange. Both are recorded twice, the write
// and the decision.
func TestNoTokenWithoutItsCredential(t *testing.T) {
	refused := kubeconfig.Refused(kubeconfig.RefusalHeldLegacy,
		status.Refused(status.CauseUsernameUnavailable, errors.New("held")))
	for _, tc := range []struct {
		name    string
		err     error
		code    int
		outcome string
	}{
		{"failed", errors.New("the apiserver is down"), http.StatusInternalServerError, audit.OutcomeFailure},
		{"refused", refused, http.StatusForbidden, audit.OutcomeDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKeys(t)
			rc, _ := apiserver(t, mapping(`{"allowed":true}`))
			h, records := k.withGenerator(t, rc, everyoneSignedIn{}, &fakeGenerator{err: tc.err})

			rec := exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil)))
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "access_token")
			assert.Equal(t, tc.outcome, auditlogtest.String(auditlogtest.OnlyAction(t, records, auditlog.ActionDelegateCredential), "krateo.audit.outcome"))
			assert.Equal(t, tc.outcome, auditlogtest.String(auditlogtest.OnlyAction(t, records, auditlog.ActionDelegate), "krateo.audit.outcome"))
		})
	}

	// Without a generator, nothing is issued at all.
	k := newKeys(t)
	rc, _ := apiserver(t, mapping(`{"allowed":true}`))
	h, _ := k.withGenerator(t, rc, everyoneSignedIn{}, nil)
	rec := exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil)))
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "access_token")
}

// An authn token whose person has no session credential any more, or one
// that records no strategy, isn't exchanged, and nothing is minted.
func TestAnAuthnTokenNeedsItsSessionCredential(t *testing.T) {
	noStrategy := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-clientconfig",
		Annotations: map[string]string{storage.ClaimAnnotation: sessionClaim("alice")}}}
	for _, tc := range []struct {
		name   string
		lookup kubeconfig.NameLookup
		cause  string
		reason string
	}{
		{"no session Secret", secrets{}, string(status.CauseSubjectNotSignedIn), "subject_not_signed_in"},
		{"no strategy recorded", secrets{"alice": noStrategy}, string(status.CauseUsernameUnavailable), "name_held_legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKeys(t)
			rc, _ := apiserver(t, mapping(`{"allowed":true}`))
			gen := &fakeGenerator{}
			h, records := k.withGenerator(t, rc, tc.lookup, gen)

			rec := exchange(h, "projected-sa-token", form(token(t, k.current, "current", time.Hour, nil)))
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.cause)
			_, n := gen.only()
			assert.Zero(t, n, "nothing minted")
			r := auditlogtest.OnlyAction(t, records, auditlog.ActionDelegate)
			assert.Equal(t, audit.OutcomeDenied, auditlogtest.String(r, "krateo.audit.outcome"))
			assert.Equal(t, tc.reason, auditlogtest.String(r, "krateo.audit.denial_reason"))
		})
	}
}
