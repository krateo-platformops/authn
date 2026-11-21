package delegate

import (
	"context"
	"errors"
	"sync"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// delegatedCall is one GenerateDelegated call.
type delegatedCall struct {
	strategy storage.Strategy
	username string
	groups   []string
	actor    string
	claim    string
	ttl      time.Duration
}

// fakeGenerator stands in for the kubeconfig generator: it records each
// delegated credential asked for and grants it for grant (an hour when
// zero), or fails with err.
type fakeGenerator struct {
	mu    sync.Mutex
	calls []delegatedCall
	grant time.Duration
	err   error
}

func (g *fakeGenerator) Generate(storage.Strategy, userinfo.Info, ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	return kubeconfig.Issued{}, errors.New("/delegate never signs anyone in")
}

func (g *fakeGenerator) GenerateStepUp(storage.Strategy, userinfo.Info, time.Duration, ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	return kubeconfig.Issued{}, errors.New("/delegate never steps anyone up")
}

func (g *fakeGenerator) GenerateDelegated(strategy storage.Strategy, u userinfo.Info, actor, claim string, ttl time.Duration, _ ...kubeconfig.IssueOption) (kubeconfig.Issued, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, delegatedCall{strategy: strategy, username: u.GetUserName(),
		groups: append([]string{}, u.GetGroups()...), actor: actor, claim: claim, ttl: ttl})
	// As the generator names a write it failed or refused: the Secret and
	// the verb it sent, or would have.
	written := storage.Written{Namespace: "krateo-system", Name: storage.DelegatedSecretName(u.GetUserName(), actor), Verb: "create"}
	if g.err != nil {
		return kubeconfig.Issued{Secret: written}, g.err
	}
	grant := g.grant
	if grant == 0 {
		grant = time.Hour
	}
	written.StatusCode, written.UID, written.ResourceVersion = 201, "uid-delegated", "1"
	return kubeconfig.Issued{NotAfter: time.Now().Add(grant), Secret: written}, nil
}

func (g *fakeGenerator) only() (delegatedCall, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.calls) != 1 {
		return delegatedCall{}, len(g.calls)
	}
	return g.calls[0], 1
}

var _ kubeconfig.Generator = (*fakeGenerator)(nil)

// sessionClaim is the claim everyoneSignedIn's session Secrets carry.
func sessionClaim(username string) string {
	return storage.EncodeClaim(storage.StrategyOIDC, "https://idp.example", "sub-"+username)
}

// everyoneSignedIn is a NameLookup in which every username has signed in
// through OIDC: its session Secret carries the strategy and a claim.
type everyoneSignedIn struct{}

func (everyoneSignedIn) SessionSecret(_ context.Context, username string) (*corev1.Secret, error) {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: username + "-clientconfig", Annotations: map[string]string{
		storage.StrategyAnnotation: string(storage.StrategyOIDC),
		storage.ClaimAnnotation:    sessionClaim(username),
	}}}, nil
}
func (everyoneSignedIn) Secret(context.Context, string) (*corev1.Secret, error) { return nil, nil }
func (everyoneSignedIn) Provisioned(context.Context, string) (bool, error)      { return false, nil }
func (everyoneSignedIn) BoundAsUser(context.Context, string) (bool, error)      { return false, nil }

var _ kubeconfig.NameLookup = everyoneSignedIn{}
