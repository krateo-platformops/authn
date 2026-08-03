package strategies

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/routes"
	authbasic "github.com/krateo-platformops/authn/internal/routes/auth/basic"
	authldap "github.com/krateo-platformops/authn/internal/routes/auth/ldap"
	authoauth "github.com/krateo-platformops/authn/internal/routes/auth/oauth"
	authoidc "github.com/krateo-platformops/authn/internal/routes/auth/oidc"

	"github.com/rs/zerolog"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func List(rc *rest.Config) routes.Route {
	return &strategiesRoute{
		rc: rc,
	}
}

const (
	Path = "/strategies"
)

var _ routes.Route = (*strategiesRoute)(nil)

type strategiesRoute struct {
	rc *rest.Config
}

func (r *strategiesRoute) Name() string {
	return "strategies"
}

func (r *strategiesRoute) Pattern() string {
	return Path
}

func (r *strategiesRoute) Method() string {
	return http.MethodGet
}

func (r *strategiesRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context()).With().
			Str("namespace", os.Getenv(util.NamespaceEnvVar)).
			Logger()

		list := []strategy{}

		if tot, err := r.countBasicAuthUsers(); err == nil {
			if tot > 0 {
				list = append(list, strategy{
					Kind: "basic", Path: authbasic.Path,
				})
			}
		}

		all, err := r.forOIDC()
		if err == nil {
			list = append(list, all...)
		} else {
			log.Err(err).Msg("unable to get oidc auth strategies")
		}

		all, err = r.forLDAP()
		if err == nil {
			list = append(list, all...)
		} else {
			log.Err(err).Msg("unable to get ldap auth strategies")
		}

		all, err = r.forOAuth()
		if err == nil {
			list = append(list, all...)
		} else {
			log.Err(err).Msg("unable to get oauth auth strategies")
		}

		wri.WriteHeader(http.StatusOK)
		wri.Header().Set("Content-Type", "application/json")

		enc := json.NewEncoder(wri)
		enc.SetIndent("", "  ")
		if err := enc.Encode(list); err != nil {
			log.Err(err).Msg("unable to serve json encoded strategy list")
		}
	}
}

func (r *strategiesRoute) countBasicAuthUsers() (int, error) {
	all, err := resolvers.UserList(r.rc)
	if err != nil {
		return 0, err
	}

	return len(all), nil
}

func (r *strategiesRoute) forOIDC() ([]strategy, error) {
	all, err := resolvers.OIDCConfigList(r.rc)
	if err != nil {
		return []strategy{}, err
	}

	if len(all.Items) == 0 {
		return []strategy{}, nil
	}

	res := make([]strategy, len(all.Items))
	for i, x := range all.Items {
		if x.Spec.Graphics == nil {
			x.Spec.Graphics = getDefaultGraphicsObject("OIDC")
		}
		res[i] = strategy{
			Kind:     "oidc",
			Path:     authoidc.Path,
			Name:     x.Name,
			Graphics: x.Spec.Graphics,
			Extensions: map[string]string{
				"authCodeURL": x.Spec.AuthorizationURL,
				"redirectURL": x.Spec.RedirectURI,
			},
		}
	}
	return res, nil
}

func (r *strategiesRoute) forLDAP() ([]strategy, error) {
	all, err := resolvers.LDAPConfigList(r.rc)
	if err != nil {
		return []strategy{}, err
	}

	if len(all.Items) == 0 {
		return []strategy{}, nil
	}

	res := make([]strategy, len(all.Items))
	for i, x := range all.Items {
		if x.Spec.Graphics == nil {
			x.Spec.Graphics = getDefaultGraphicsObject("LDAP")
		}
		res[i] = strategy{
			Kind:     "ldap",
			Path:     authldap.Path,
			Name:     x.Name,
			Graphics: x.Spec.Graphics,
		}
	}
	return res, nil
}

func (r *strategiesRoute) forOAuth() ([]strategy, error) {
	dyn, err := dynamic.NewForConfig(r.rc)
	if err != nil {
		return []strategy{}, err
	}

	all, err := resolvers.ListOAuthConfigs(dyn)
	if err != nil {
		return []strategy{}, err
	}

	res := make([]strategy, len(all))
	for i, x := range all {
		if x.Graphics == nil {
			x.Graphics = getDefaultGraphicsObject("OAuth2")
		}
		res[i] = strategy{
			Kind:     "oauth",
			Path:     authoauth.Path,
			Name:     x.Name,
			Graphics: x.Graphics,
			Extensions: map[string]string{
				"authCodeURL": x.AuthCodeURL,
				"redirectURL": x.RedirectURL,
			},
		}
	}
	return res, nil
}

type strategy struct {
	Kind       string            `json:"kind"`
	Name       string            `json:"name,omitempty"`
	Graphics   *core.Graphics    `json:"graphics,omitempty"`
	Path       string            `json:"path"`
	Extensions map[string]string `json:"extensions,omitempty"`
}
