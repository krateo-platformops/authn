package resolvers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// ErrIssuerConflict reports an OIDCConfig whose spec.issuer differs from the
// issuer its discovery document advertises.
var ErrIssuerConflict = errors.New("spec.issuer differs from the discovered issuer")

type DiscoveryEndpointResponse struct {
	Issuer                 string `json:"issuer"`
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
	if err != nil {
		return nil, err
	}

	return res, resolveOIDCConfig(ctx, res)
}

// resolveOIDCConfig completes cfg for a login: the endpoints, and the issuer
// the ID token is validated against. With a discoveryURL the discovery
// document is always read, because it is where the issuer comes from. Its
// endpoints are applied only when some endpoint is not set, as before.
// cfg.Spec.Issuer stays empty when neither spec.issuer nor discovery provides
// one; the login refuses such a config.
func resolveOIDCConfig(ctx context.Context, cfg *oidcv1alpha1.OIDCConfig) error {
	if cfg.Spec.DiscoveryURL == "" {
		if cfg.Spec.AuthorizationURL != "" && !strings.Contains(cfg.Spec.AuthorizationURL, "?") {
			cfg.Spec.AuthorizationURL = authCodeURL(cfg)
		}
		return nil
	}

	doc, err := fetchDiscovery(ctx, cfg.Spec.DiscoveryURL)
	if err != nil {
		return err
	}

	switch {
	case cfg.Spec.Issuer == "":
		cfg.Spec.Issuer = doc.Issuer
	case doc.Issuer != "" && doc.Issuer != cfg.Spec.Issuer:
		return fmt.Errorf("%w: spec.issuer %q, discovery %q", ErrIssuerConflict, cfg.Spec.Issuer, doc.Issuer)
	}

	if cfg.Spec.AuthorizationURL == "" || cfg.Spec.TokenURL == "" || cfg.Spec.UserInfoURL == "" {
		return applyDiscovery(cfg, doc)
	}
	if !strings.Contains(cfg.Spec.AuthorizationURL, "?") {
		cfg.Spec.AuthorizationURL = authCodeURL(cfg)
	}
	return nil
}

func OIDCConfigList(rc *rest.Config) (*oidcv1alpha1.OIDCConfigList, error) {
	res, err := listOIDCConfigs(context.Background(), rc)
	if err != nil {
		return res, err
	}

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

// OIDCConfigsWithoutIssuer names the OIDCConfigs in the operator namespace
// that set neither spec.issuer nor spec.discoveryURL. authn has no issuer to
// validate their ID tokens against, so their logins are refused.
func OIDCConfigsWithoutIssuer(ctx context.Context, rc *rest.Config) ([]string, error) {
	all, err := listOIDCConfigs(ctx, rc)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, item := range all.Items {
		if item.Spec.Issuer == "" && item.Spec.DiscoveryURL == "" {
			names = append(names, item.Name)
		}
	}
	return names, nil
}

// listOIDCConfigs lists the OIDCConfigs in the operator namespace as stored,
// without discovery.
func listOIDCConfigs(ctx context.Context, rc *rest.Config) (*oidcv1alpha1.OIDCConfigList, error) {
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
		Do(ctx).
		Into(res)
	return res, err
}

func doDiscovery(ctx context.Context, cfg *oidcv1alpha1.OIDCConfig) error {
	// Use the discovery API to find the TokenURL and UserInfoURL, if present
	if cfg.Spec.DiscoveryURL != "" {
		doc, err := fetchDiscovery(ctx, cfg.Spec.DiscoveryURL)
		if err != nil {
			return err
		}
		return applyDiscovery(cfg, doc)
	}
	return applyDiscovery(cfg, DiscoveryEndpointResponse{})
}

func fetchDiscovery(ctx context.Context, discoveryURL string) (DiscoveryEndpointResponse, error) {
	var doc DiscoveryEndpointResponse
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return doc, fmt.Errorf("failed to create http request for discovery endpoint: %v", err)
	}
	resp, err := telemetry.HTTPClient().Do(request)
	if err != nil {
		return doc, fmt.Errorf("failed to send discovery request: %v", err)
	}
	defer resp.Body.Close()
	endpointsDataJson, err := io.ReadAll(resp.Body)
	if err != nil {
		return doc, fmt.Errorf("failed to read discovery response: %v", err)
	}
	if err := json.Unmarshal(endpointsDataJson, &doc); err != nil {
		return doc, fmt.Errorf("failed to unmarshal discovery response: %v", err)
	}
	return doc, nil
}

// applyDiscovery fills cfg's endpoints from the discovery document and checks
// that the authorize and token endpoints are known.
func applyDiscovery(cfg *oidcv1alpha1.OIDCConfig, endpointsData DiscoveryEndpointResponse) error {
	if endpointsData.Authorization_endpoint != "" {
		cfg.Spec.AuthorizationURL = endpointsData.Authorization_endpoint
	}

	if endpointsData.Token_endpoint != "" {
		cfg.Spec.TokenURL = endpointsData.Token_endpoint
	}

	if endpointsData.Userinfo_endpoint != "" {
		cfg.Spec.UserInfoURL = endpointsData.Userinfo_endpoint
	}

	if (cfg.Spec.TokenURL == "" || cfg.Spec.AuthorizationURL == "") && cfg.Spec.DiscoveryURL == "" {
		return fmt.Errorf("url for discovery and authorize/token endpoints cannot be empty")
	} else if cfg.Spec.TokenURL == "" || cfg.Spec.AuthorizationURL == "" {
		return fmt.Errorf("url for authorize/token endpoint cannot be empty")
	}

	cfg.Spec.AuthorizationURL = authCodeURL(cfg)

	return nil
}

// newState returns 32 random bytes, base64url-encoded without padding.
func newState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+); it panics instead
	return base64.RawURLEncoding.EncodeToString(b)
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
	// Space-separated with no stray spaces: an empty or padded
	// additionalScopes used to leave a trailing space in scope.
	v.Set("scope", strings.Join(strings.Fields("openid email profile "+cfg.Spec.AdditionalScopes), " "))

	// state is printable: raw random bytes put binary, sometimes a NUL, in the
	// URL, and Keycloak answers 400 to a state containing a NUL (about 1 URL
	// in 8).
	v.Set("state", newState())

	if strings.Contains(cfg.Spec.AuthorizationURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}
