package storage

import (
	"context"
	"fmt"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/plumbing/kubeutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

const (
	ClientCertLabel = "client-certificate-data"
	ClientKeyLabel  = "client-key-data"
	CALabel         = "certificate-authority-data"
	ProxyUrlLabel   = "proxy-url"
	ServerUrlLabel  = "server-url"
)

type AuthInfo struct {
	Server   string `json:"server"`
	ProxyURL string `json:"proxy-url,omitempty"`
	CAData   string `json:"certificate-authority-data"`
	CertData string `json:"client-certificate-data"`
	KeyData  string `json:"client-key-data"`
}

type AuthInfoStorage interface {
	Put(name string, nfo *AuthInfo) error
	Get(name string) (*AuthInfo, error)
}

func Default(rc *rest.Config) AuthInfoStorage {
	return &secretStore{rc: rc}
}

var _ AuthInfoStorage = (*secretStore)(nil)

type secretStore struct {
	rc *rest.Config
}

func (st *secretStore) Put(name string, nfo *AuthInfo) error {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	sec := corev1.Secret{}
	sec.SetName(fmt.Sprintf("%s-clientconfig", kubeutil.MakeDNS1123Compatible(name)))
	sec.SetNamespace(ns)
	sec.StringData = map[string]string{
		CALabel:         nfo.CAData,
		ClientCertLabel: nfo.CertData,
		ClientKeyLabel:  nfo.KeyData,
		ServerUrlLabel:  nfo.Server,
		ProxyUrlLabel:   nfo.ProxyURL,
	}

	err = secrets.Create(context.TODO(), st.rc, &sec)
	if err == nil {
		return nil
	}

	if !errors.IsAlreadyExists(err) {
		return err
	}

	return secrets.Update(context.TODO(), st.rc, &sec)
}

func (st *secretStore) Get(name string) (*AuthInfo, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	sec, err := secrets.Get(context.TODO(), st.rc,
		&core.SecretKeySelector{
			Namespace: ns,
			Name:      fmt.Sprintf("%s-clientconfig", kubeutil.MakeDNS1123Compatible(name)),
		})
	if err != nil {
		return nil, err
	}

	nfo := &AuthInfo{}

	crt, ok := sec.Data[ClientCertLabel]
	if !ok {
		return nfo, fmt.Errorf("%s not found (secret: %s, namespace:%s)", ClientCertLabel, name, ns)
	}
	nfo.CertData = string(crt)

	key, ok := sec.Data[ClientKeyLabel]
	if !ok {
		return nfo, fmt.Errorf("%s not found (secret: %s, namespace:%s)", ClientKeyLabel, name, ns)
	}
	nfo.KeyData = string(key)

	srv, ok := sec.Data[ServerUrlLabel]
	if !ok {
		return nfo, fmt.Errorf("%s not found (secret: %s, namespace:%s)", ServerUrlLabel, name, ns)
	}
	nfo.Server = string(srv)

	prx, ok := sec.Data[ProxyUrlLabel]
	if !ok {
		return nfo, fmt.Errorf("%s not found (secret: %s, namespace:%s)", ProxyUrlLabel, name, ns)
	}
	nfo.ProxyURL = string(prx)

	ca, ok := sec.Data[CALabel]
	if !ok {
		return nfo, fmt.Errorf("%s not found (secret: %s, namespace:%s)", CALabel, name, ns)
	}
	nfo.CAData = string(ca)

	return nfo, nil
}
