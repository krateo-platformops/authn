package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/configmaps"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/rs/zerolog"
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
	// storage.IdentityAnnotations).
	Generate(strategy storage.Strategy, user userinfo.Info) (dat []byte, notAfter time.Time, err error)

	// GenerateStepUp mints a short-lived step-up credential (#49) for user,
	// who must have been built by userinfo.NewStepUpUser, and stores it as
	// the `<username>-clientconfig-stepup` Secret. The user's session Secret is
	// not touched, and no kubeconfig is returned. ttl is the requested
	// lifetime. The returned notAfter is the granted one, which bounds the
	// step-up JWT.
	GenerateStepUp(strategy storage.Strategy, user userinfo.Info, ttl time.Duration) (notAfter time.Time, err error)
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
}

func (g *kubeconfigGenerator) Generate(strategy storage.Strategy, userInfo userinfo.Info) ([]byte, time.Time, error) {
	var notAfter time.Time

	if err := g.checkGroups(userInfo, false); err != nil {
		return nil, notAfter, err
	}

	certInfo, clusterInfo, notAfter, err := g.issue(strategy, userInfo, g.certDuration, false)
	if err != nil {
		return nil, notAfter, err
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
		return nil, notAfter, fmt.Errorf("converting generated config to json: %w", err)
	}

	return out, notAfter, nil
}

func (g *kubeconfigGenerator) GenerateStepUp(strategy storage.Strategy, userInfo userinfo.Info, ttl time.Duration) (time.Time, error) {
	if err := g.checkGroups(userInfo, true); err != nil {
		return time.Time{}, err
	}
	_, _, notAfter, err := g.issue(strategy, userInfo, ttl, true)
	return notAfter, err
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
func (g *kubeconfigGenerator) issue(strategy storage.Strategy, userInfo userinfo.Info, duration time.Duration, stepUp bool) (CertInfo, ClusterInfo, time.Time, error) {
	if len(g.caData) == 0 {
		caCrt, err := configmaps.CACrt(context.Background(), g.restconfig)
		if err != nil {
			return CertInfo{}, ClusterInfo{}, time.Time{}, err
		}
		g.caData = caCrt
	}

	certInfo, clusterInfo, notAfter, err := g.generateCertAndClusterInfo(userInfo, duration)
	if err != nil {
		return certInfo, clusterInfo, notAfter, err
	}

	err = g.storeCertAndClusterInfo(strategy, userInfo.GetUserName(), certInfo, clusterInfo, stepUp)
	return certInfo, clusterInfo, notAfter, err
}

func (g *kubeconfigGenerator) storeCertAndClusterInfo(strategy storage.Strategy, name string, certInfo CertInfo, clusterInfo ClusterInfo, stepUp bool) error {
	nfo := storage.AuthInfo{
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
