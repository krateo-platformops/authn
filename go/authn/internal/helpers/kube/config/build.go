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
	Generate(user userinfo.Info) ([]byte, error)
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

func (g *kubeconfigGenerator) Generate(userInfo userinfo.Info) ([]byte, error) {
	if len(g.caData) == 0 {
		caCrt, err := configmaps.CACrt(context.Background(), g.restconfig)
		if err != nil {
			return nil, err
		}
		g.caData = caCrt
	}

	certInfo, clusterInfo, err := g.generateCertAndClusterInfo(userInfo)
	if err != nil {
		return nil, err
	}

	err = g.storeCertAndClusterInfo(userInfo.GetUserName(), certInfo, clusterInfo)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("converting generated config to json: %w", err)
	}

	return out, nil
}

func (g *kubeconfigGenerator) storeCertAndClusterInfo(name string, certInfo CertInfo, clusterInfo ClusterInfo) error {
	nfo := storage.AuthInfo{
		CertData: certInfo.ClientCertificateData,
		KeyData:  certInfo.ClientKeyData,
		CAData:   clusterInfo.CertificateAuthorityData,
		Server:   clusterInfo.Server,
		ProxyURL: clusterInfo.ProxyURL,
	}

	return g.store.Put(name, &nfo)
}

func (g *kubeconfigGenerator) generateCertAndClusterInfo(userInfo userinfo.Info) (certInfo CertInfo, clusterInfo ClusterInfo, err error) {
	if len(g.kubernetesURL) == 0 {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if len(host) == 0 || len(port) == 0 {
			return certInfo, clusterInfo, rest.ErrNotInCluster
		}
		g.kubernetesURL = "https://" + net.JoinHostPort(host, port)
	}

	cli, err := kubernetes.NewForConfig(g.restconfig)
	if err != nil {
		return certInfo, clusterInfo, err
	}

	cert, key, err := generateClientCertAndKey(cli, g.log, generateClientCertAndKeyOpts{
		userID:   userInfo.GetID(),
		username: userInfo.GetUserName(),
		groups:   userInfo.GetGroups(),
		duration: g.certDuration,
	})
	if err != nil {
		return certInfo, clusterInfo, err
	}

	clusterInfo.CertificateAuthorityData = g.caData
	//clusterInfo.ProxyURL = g.proxyURL
	clusterInfo.Server = g.kubernetesURL

	certInfo.ClientCertificateData = cert
	certInfo.ClientKeyData = key

	return
}
