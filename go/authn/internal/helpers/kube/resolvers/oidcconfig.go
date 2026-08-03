package resolvers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	oidcv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oidc/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube/client"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/telemetry"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

type DiscoveryEndpointResponse struct {
	Authorization_endpoint string `json:"authorization_endpoint"`
	Token_endpoint         string `json:"token_endpoint"`
	Userinfo_endpoint      string `json:"userinfo_endpoint"`
}

func OIDCConfigGet(ctx context.Context, rc *rest.Config, name string) (*oidcv1alpha1.OIDCConfig, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	cli, err := client.New(rc, schema.GroupVersion{
		Group:   oidcv1alpha1.Group,
		Version: oidcv1alpha1.Version,
	})
	if err != nil {
		return nil, err
	}

	res := &oidcv1alpha1.OIDCConfig{}
	err = cli.Get().Resource("oidcconfigs").
		Namespace(ns).Name(name).
		Do(context.Background()).
		Into(res)

	if (res.Spec.AuthorizationURL == "" || res.Spec.TokenURL == "" || res.Spec.UserInfoURL == "") && res.Spec.DiscoveryURL != "" {
		err = doDiscovery(ctx, res)
	} else if res.Spec.AuthorizationURL != "" && !strings.Contains(res.Spec.AuthorizationURL, "?") {
		res.Spec.AuthorizationURL = authCodeURL(res)
	}

	return res, err
}

func OIDCConfigList(rc *rest.Config) (*oidcv1alpha1.OIDCConfigList, error) {
	ns, err := util.GetOperatorNamespace()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve service namespace: %w", err)
	}

	cli, err := client.New(rc, schema.GroupVersion{
		Group:   oidcv1alpha1.Group,
		Version: oidcv1alpha1.Version,
	})
	if err != nil {
		return nil, err
	}

	res := &oidcv1alpha1.OIDCConfigList{}
	err = cli.Get().Resource("oidcconfigs").
		Namespace(ns).
		Do(context.Background()).
		Into(res)

	for i, item := range res.Items {
		if (item.Spec.AuthorizationURL == "" || item.Spec.TokenURL == "" || item.Spec.UserInfoURL == "") && item.Spec.DiscoveryURL != "" {
			err = doDiscovery(context.Background(), &item)
			res.Items[i].Spec.AuthorizationURL = item.Spec.AuthorizationURL
			res.Items[i].Spec.TokenURL = item.Spec.TokenURL
			res.Items[i].Spec.UserInfoURL = item.Spec.UserInfoURL
		} else if item.Spec.AuthorizationURL != "" && !strings.Contains(item.Spec.AuthorizationURL, "?") {
			res.Items[i].Spec.AuthorizationURL = authCodeURL(&item)
		}
	}

	return res, err
}

func doDiscovery(ctx context.Context, cfg *oidcv1alpha1.OIDCConfig) error {
	// Use the discovery API to find the TokenURL and UserInfoURL, if present
	if cfg.Spec.DiscoveryURL != "" {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Spec.DiscoveryURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create http request for discovery endpoint: %v", err)
		}
		resp, err := telemetry.HTTPClient().Do(request)
		if err != nil {
			return fmt.Errorf("failed to send discovery request: %v", err)
		}
		endpointsDataJson, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read discovery response: %v", err)
		}

		var endpointsData DiscoveryEndpointResponse
		err = json.Unmarshal(endpointsDataJson, &endpointsData)
		if err != nil {
			return fmt.Errorf("failed to unmarshal discovery response: %v", err)
		}

		if endpointsData.Authorization_endpoint != "" {
			cfg.Spec.AuthorizationURL = endpointsData.Authorization_endpoint
		}

		if endpointsData.Token_endpoint != "" {
			cfg.Spec.TokenURL = endpointsData.Token_endpoint
		}

		if endpointsData.Userinfo_endpoint != "" {
			cfg.Spec.UserInfoURL = endpointsData.Userinfo_endpoint
		}
	}

	if (cfg.Spec.TokenURL == "" || cfg.Spec.AuthorizationURL == "") && cfg.Spec.DiscoveryURL == "" {
		return fmt.Errorf("url for discovery and authorize/token endpoints cannot be empty")
	} else if cfg.Spec.TokenURL == "" || cfg.Spec.AuthorizationURL == "" {
		return fmt.Errorf("url for authorize/token endpoint cannot be empty")
	}

	cfg.Spec.AuthorizationURL = authCodeURL(cfg)

	return nil
}

func authCodeURL(cfg *oidcv1alpha1.OIDCConfig) string {
	var buf bytes.Buffer
	buf.WriteString(cfg.Spec.AuthorizationURL)
	v := url.Values{
		"response_type": {"code"},
		"response_mode": {"query"},
		"client_id":     {cfg.Spec.ClientID},
	}
	if cfg.Spec.RedirectURI != "" {
		v.Set("redirect_uri", cfg.Spec.RedirectURI)
	}
	v.Set("scope", "openid email profile "+cfg.Spec.AdditionalScopes)

	b := make([]byte, 32)
	rand.Read(b)
	state := string(b)
	if state != "" {
		v.Set("state", state)
	}

	if strings.Contains(cfg.Spec.AuthorizationURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}
