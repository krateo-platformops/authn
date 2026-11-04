package oauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/status"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

type userInfo struct {
	name              string
	email             string
	preferredUsername string
	groups            []string
	avatarURL         string
}

func getConfig(rc *rest.Config, name string) (*oauth2.Config, *core.ObjectRef, error) {
	if len(rest.IsValidPathSegmentName(name)) > 0 {
		// No OAuthConfig can have this name; looking it up would fail client-side.
		return nil, nil, status.CauseError{Code: http.StatusNotFound, Cause: CauseOAuthConfigNotFound,
			Err: fmt.Errorf("OAuthConfig %q not found", name)}
	}
	ghc, err := resolvers.GetOAuthConfig(rc, name)
	switch {
	case apierrors.IsNotFound(err):
		return nil, nil, status.CauseError{Code: http.StatusNotFound, Cause: CauseOAuthConfigNotFound,
			Err: fmt.Errorf("OAuthConfig %q not found", name)}
	case err != nil:
		return nil, nil, status.Failed(CauseOAuthConfigLookupFailed, fmt.Errorf("unable to resolve OAuth configuration: %w", err))
	}

	sec, err := secrets.Get(context.Background(), rc, ghc.Spec.ClientSecretRef)
	if err != nil {
		return nil, nil, status.Failed(CauseClientSecretLookupFailed, fmt.Errorf("unable to read the client secret: %w", err))
	}

	clientSecret, ok := sec.Data[ghc.Spec.ClientSecretRef.Key]
	if !ok {
		return nil, nil, status.Failed(CauseClientSecretLookupFailed,
			fmt.Errorf("the client secret has no key %q", ghc.Spec.ClientSecretRef.Key))
	}

	return &oauth2.Config{
		ClientID:     ghc.Spec.ClientID,
		ClientSecret: string(clientSecret),
		RedirectURL:  ghc.Spec.RedirectURL,
		Scopes:       ghc.Spec.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  ghc.Spec.AuthURL,
			TokenURL: ghc.Spec.TokenURL,
		},
	}, ghc.Spec.RESTActionRef, nil
}

func updateConfig(config userInfo, additionalFieldstoReplace map[string]interface{}) (userInfo, error) {
	for key := range additionalFieldstoReplace {
		if additionalFieldstoReplace[key] != nil {
			switch key {
			case "name":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}
				config.name = v
			case "email":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}
				config.email = v
			case "preferredUsername":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}
				config.preferredUsername = v
			case "groups":
				groups := make([]string, 0)
				v, ok := additionalFieldstoReplace[key].([]interface{})
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type array", key)
				}
				for _, i := range v {
					if _, okk := i.(string); !okk {
						return config, fmt.Errorf("error parsing updated config: %s is not type string array", key)
					}
					groups = append(groups, i.(string))
				}
				config.groups = groups
			case "avatarURL":
				v, ok := additionalFieldstoReplace[key].(string)
				if !ok {
					return config, fmt.Errorf("error parsing updated config: %s is not type string", key)
				}

				config.avatarURL = v

			}
		}
	}
	return config, nil
}
