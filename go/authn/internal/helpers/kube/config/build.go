package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/configmaps"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Generator interface {
	// Generate mints a client certificate for user, stores it as a
	// `<username>-clientconfig` Secret and returns the kubeconfig document
	// together with the certificate's REAL expiry. The signer may grant less
	// than the requested duration, so callers must bound anything derived from
	// the credential — the login JWT above all — by the returned notAfter and
	// never by the duration they asked for.
	//
	// strategy is the login strategy issuing the credential; it is recorded on
	// the Secret together with the certificate's groups (see
	// storage.IdentityAnnotations). opts adjust how the Secret is stored; see
	// OwnedBy.
	Generate(strategy storage.Strategy, user userinfo.Info, opts ...IssueOption) (Issued, error)

	// GenerateStepUp mints a short-lived step-up credential (#49) for user,
	// who must have been built by userinfo.NewStepUpUser, and stores it as
	// the `<username>-clientconfig-stepup` Secret. The user's session Secret is
	// not touched, and no kubeconfig is returned. ttl is the requested
	// lifetime. The returned notAfter is the granted one, which bounds the
	// step-up JWT.
	GenerateStepUp(strategy storage.Strategy, user userinfo.Info, ttl time.Duration, opts ...IssueOption) (Issued, error)
}

// Issued is the outcome of one Generate or GenerateStepUp, for the caller's
// audit record (AUDIT-4) as much as for its answer.
type Issued struct {
	// Kubeconfig is the session kubeconfig document. Nil for a step-up, and on
	// an error.
	Kubeconfig []byte
	// NotAfter is the certificate's granted expiry, which bounds the JWT.
	NotAfter time.Time
	// Secret names the credential Secret. On success it is the write: the verb
	// sent, the apiserver's status, the stored uid. On a refusal (RefusalOf
	// the error) or a failure before the write, it is the Secret the issuance
	// would have written and the verb it would have sent, with no status. It
	// names the Secret whenever the identity has a username; one without names
	// none.
	Secret storage.Written
}

// IssueOption adjusts how one issued credential is stored.
type IssueOption func(*IssueOptions)

// IssueOptions is what a list of IssueOption resolves to.
type IssueOptions struct {
	// Owner becomes the stored Secret's ownerReference (see OwnedBy).
	Owner *metav1.OwnerReference
	// Admit holds the caller's own admission checks (see Admit).
	Admit []func(userinfo.Info) error
}

// Admit adds an admission check the identity must pass before anything is
// minted, after the reserved-group check and before the name guard. A check
// refuses with an error built by Refused, so the refusal reaches the audit
// record as a denial with its reason; any other error is a failure.
func Admit(check func(userinfo.Info) error) IssueOption {
	return func(o *IssueOptions) { o.Admit = append(o.Admit, check) }
}

// NewIssueOptions applies opts in order.
func NewIssueOptions(opts ...IssueOption) IssueOptions {
	var o IssueOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// OwnedBy makes owner the stored Secret's ownerReference, so the Kubernetes
// garbage collector deletes the credential with its owner. The serviceaccount
// login passes the identity's ServiceAccount mapping: retiring the mapping then
// retires the credential, with no one else needing delete rights on Secrets.
func OwnedBy(owner metav1.OwnerReference) IssueOption {
	return func(o *IssueOptions) { o.Owner = &owner }
}

type GeneratorOption func(*kubeconfigGenerator)

func CAData(v string) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.caData = v
	}
}

func ProxyURL(v string) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.proxyURL = v
	}
}

func ClusterName(v string) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.clusterName = v
	}
}

func KubernetesURL(v string) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.kubernetesURL = v
	}
}

func CertDuration(v time.Duration) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.certDuration = v
	}
}

func Log(l zerolog.Logger) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.log = l
	}
}

func Storage(s storage.AuthInfoStorage) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.store = s
	}
}

// Lookup replaces the cluster reads the name guard decides from (see
// nameGuard). Tests use it; authn reads the cluster.
func Lookup(l NameLookup) GeneratorOption {
	return func(g *kubeconfigGenerator) {
		g.lookup = l
	}
}

func NewGenerator(restConfig *rest.Config, opts ...GeneratorOption) Generator {
	gen := &kubeconfigGenerator{
		restconfig: restConfig,
	}

	for _, fn := range opts {
		fn(gen)
	}

	if gen.store == nil {
		gen.store = storage.Default(gen.restconfig)
	}
	if gen.lookup == nil {
		l, err := newClusterLookup(gen.restconfig)
		if err != nil {
			gen.lookupErr = err
		} else {
			gen.lookup = l
		}
	}

	return gen
}

var _ Generator = (*kubeconfigGenerator)(nil)

type kubeconfigGenerator struct {
	caData        string
	proxyURL      string
	clusterName   string
	kubernetesURL string
	certDuration  time.Duration
	restconfig    *rest.Config
	store         storage.AuthInfoStorage
	log           zerolog.Logger
	lookup        NameLookup
	lookupErr     error
}

// admit checks user's groups for `system:` ones, then asks the name guard
// whether user's username may be issued to it, and returns the claim to
// record.
// refuseGroups refuses an identity by its own groups: a system: group, or a
// krateo: group asserted by an identity source. It reads nothing, and runs
// before every admission check (Admit), so the identity is refused for what it
// is before its assurance or a provider's allowedGroups is evaluated: a
// system: group is never reported as a step-up or allowedGroups refusal
// (authn#133 review).
func refuseGroups(strategy storage.Strategy, user userinfo.Info) error {
	if err := checkSystemGroups(user); err != nil {
		return err
	}
	return checkPlatformGroups(strategy, user)
}

func (g *kubeconfigGenerator) admit(strategy storage.Strategy, user userinfo.Info) (string, error) {
	if g.lookupErr != nil {
		return "", fmt.Errorf("building the name guard's cluster client: %w", g.lookupErr)
	}
	guard := nameGuard{lookup: g.lookup, log: g.log}
	return guard.admit(context.Background(), strategy, user)
}

func (g *kubeconfigGenerator) Generate(strategy storage.Strategy, userInfo userinfo.Info, opts ...IssueOption) (Issued, error) {
	target := secretFor(userInfo, storage.ClientConfigSecretName)
	o := NewIssueOptions(opts...)
	if err := g.checkGroups(userInfo, false); err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}
	if err := refuseGroups(strategy, userInfo); err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}
	if err := o.CheckAdmit(userInfo); err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}
	claim, err := g.admit(strategy, userInfo)
	if err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}

	certInfo, clusterInfo, notAfter, written, err := g.issue(strategy, userInfo, g.certDuration, false, o.Owner, claim)
	if err != nil {
		return Issued{NotAfter: notAfter, Secret: g.orWouldWrite(written, target)}, err
	}

	c := KubeConfig{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters: Clusters{
			0: {
				Cluster: clusterInfo,
				Name:    g.clusterName,
			},
		},
		Contexts: Contexts{
			0: {
				Context: Context{
					Cluster: g.clusterName,
					User:    userInfo.GetUserName(),
				},
				Name: g.clusterName,
			},
		},
		CurrentContext: g.clusterName,
		Users: Users{
			0: {
				CertInfo: certInfo,
				Name:     userInfo.GetUserName(),
			},
		},
	}

	out, err := json.Marshal(c)
	if err != nil {
		// The Secret is stored; only the response document failed.
		return Issued{NotAfter: notAfter, Secret: written}, fmt.Errorf("converting generated config to json: %w", err)
	}

	return Issued{Kubeconfig: out, NotAfter: notAfter, Secret: written}, nil
}

func (g *kubeconfigGenerator) GenerateStepUp(strategy storage.Strategy, userInfo userinfo.Info, ttl time.Duration, opts ...IssueOption) (Issued, error) {
	target := secretFor(userInfo, storage.StepUpSecretName)
	o := NewIssueOptions(opts...)
	if err := g.checkGroups(userInfo, true); err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}
	if err := refuseGroups(strategy, userInfo); err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}
	if err := o.CheckAdmit(userInfo); err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}
	claim, err := g.admit(strategy, userInfo)
	if err != nil {
		return Issued{Secret: g.wouldWrite(target)}, err
	}
	_, _, notAfter, written, err := g.issue(strategy, userInfo, ttl, true, nil, claim)
	if err != nil {
		return Issued{NotAfter: notAfter, Secret: g.orWouldWrite(written, target)}, err
	}
	return Issued{NotAfter: notAfter, Secret: written}, nil
}

// CheckAdmit runs o's admission checks (Admit) on user, in order, and returns
// the first refusal.
func (o IssueOptions) CheckAdmit(user userinfo.Info) error {
	for _, check := range o.Admit {
		if err := check(user); err != nil {
			return err
		}
	}
	return nil
}

// wouldWrite names the Secret an issuance that stopped before writing would
// have written, with the verb it would have sent: update when the Secret
// exists (Put's create is answered 409 and it updates), create otherwise. When
// the namespace or the Secret can't be read, the verb is left empty rather
// than guessed.
func (g *kubeconfigGenerator) wouldWrite(name string) storage.Written {
	w := storage.Written{Name: name}
	if ns, err := util.GetOperatorNamespace(); err == nil {
		w.Namespace = ns
	}
	if name == "" || w.Namespace == "" || g.lookup == nil {
		// With no name (an identity with no username) only the namespace is
		// known; without the namespace or a lookup the Secret can't be read.
		// Either way the verb isn't known, so it is left empty.
		return w
	}
	sec, err := g.lookup.Secret(context.Background(), name)
	switch {
	case err != nil:
	case sec != nil:
		w.Verb = "update"
	default:
		w.Verb = "create"
	}
	return w
}

// secretFor is name(user's username), or "" for an identity with no username,
// which no Secret can be named for.
func secretFor(user userinfo.Info, name func(string) string) string {
	if user.GetUserName() == "" {
		return ""
	}
	return name(user.GetUserName())
}

// orWouldWrite is written when Put sent a request, else wouldWrite(name).
func (g *kubeconfigGenerator) orWouldWrite(written storage.Written, name string) storage.Written {
	if written.Verb != "" {
		return written
	}
	return g.wouldWrite(name)
}

// checkGroups refuses, before anything is minted, an identity whose groups
// can't be issued. Reserved groups (userinfo.ReservedGroupPrefix) are authn's
// to grant: the ones an identity source tried to assert are reported, a
// session credential may carry none, and a step-up credential must carry one.
// A session identity that still has one was built without userinfo's guard,
// and must fail loudly rather than be granted.
func (g *kubeconfigGenerator) checkGroups(userInfo userinfo.Info, stepUp bool) error {
	// An identity whose groups cannot be recorded faithfully on its Secret
	// must not be issued at all.
	if err := storage.ValidateGroups(userInfo.GetGroups()); err != nil {
		return err
	}

	if dropped := userInfo.DroppedGroups(); len(dropped) > 0 {
		g.log.Warn().
			Str("username", userInfo.GetUserName()).
			Strs("groups", dropped).
			Msg("dropped reserved groups asserted by the identity source")
	}

	reserved := 0
	for _, grp := range userInfo.GetGroups() {
		if !userinfo.IsReserved(grp) {
			continue
		}
		if !stepUp {
			return fmt.Errorf("group %q is reserved to authn and cannot be issued by a login", grp)
		}
		reserved++
	}
	if stepUp && reserved == 0 {
		return fmt.Errorf("a step-up credential must carry a %s group", userinfo.ReservedGroupPrefix)
	}
	return nil
}

// issue mints a certificate for userInfo valid for duration and stores it as
// the user's session or step-up credential.
func (g *kubeconfigGenerator) issue(strategy storage.Strategy, userInfo userinfo.Info, duration time.Duration, stepUp bool, owner *metav1.OwnerReference, claim string) (CertInfo, ClusterInfo, time.Time, storage.Written, error) {
	if len(g.caData) == 0 {
		caCrt, err := configmaps.CACrt(context.Background(), g.restconfig)
		if err != nil {
			return CertInfo{}, ClusterInfo{}, time.Time{}, storage.Written{}, err
		}
		g.caData = caCrt
	}

	certInfo, clusterInfo, notAfter, err := g.generateCertAndClusterInfo(userInfo, duration)
	if err != nil {
		return certInfo, clusterInfo, notAfter, storage.Written{}, err
	}

	written, err := g.storeCertAndClusterInfo(strategy, userInfo.GetUserName(), certInfo, clusterInfo, stepUp, owner, claim)
	if errors.Is(err, storage.ErrClaimedByAnother) {
		// Another identity claimed the name between the guard and this write.
		// The certificate just minted is never stored or returned.
		g.log.Warn().Str("username", userInfo.GetUserName()).Str("claim", claim).Err(err).Msg("username refused")
		err = refused(RefusalClaimed, status.RefusedPrivately(status.CauseUsernameUnavailable,
			fmt.Errorf("the username %q isn't available to this identity", userInfo.GetUserName()), err))
	}
	return certInfo, clusterInfo, notAfter, written, err
}

func (g *kubeconfigGenerator) storeCertAndClusterInfo(strategy storage.Strategy, name string, certInfo CertInfo, clusterInfo ClusterInfo, stepUp bool, owner *metav1.OwnerReference, claim string) (storage.Written, error) {
	nfo := storage.AuthInfo{
		Claim:    claim,
		Owner:    owner,
		StepUp:   stepUp,
		Strategy: strategy,
		CertData: certInfo.ClientCertificateData,
		KeyData:  certInfo.ClientKeyData,
		CAData:   clusterInfo.CertificateAuthorityData,
		Server:   clusterInfo.Server,
		ProxyURL: clusterInfo.ProxyURL,
	}

	return g.store.Put(name, &nfo)
}

func (g *kubeconfigGenerator) generateCertAndClusterInfo(userInfo userinfo.Info, duration time.Duration) (certInfo CertInfo, clusterInfo ClusterInfo, notAfter time.Time, err error) {
	if len(g.kubernetesURL) == 0 {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if len(host) == 0 || len(port) == 0 {
			return certInfo, clusterInfo, notAfter, rest.ErrNotInCluster
		}
		g.kubernetesURL = "https://" + net.JoinHostPort(host, port)
	}

	cli, err := kubernetes.NewForConfig(g.restconfig)
	if err != nil {
		return certInfo, clusterInfo, notAfter, err
	}

	cert, key, leaf, err := generateClientCertAndKey(cli, g.log, generateClientCertAndKeyOpts{
		userID:   userInfo.GetID(),
		username: userInfo.GetUserName(),
		groups:   userInfo.GetGroups(),
		duration: duration,
	})
	if err != nil {
		return certInfo, clusterInfo, notAfter, err
	}
	notAfter = leaf.NotAfter

	clusterInfo.CertificateAuthorityData = g.caData
	//clusterInfo.ProxyURL = g.proxyURL
	clusterInfo.Server = g.kubernetesURL

	certInfo.ClientCertificateData = cert
	certInfo.ClientKeyData = key

	return
}
