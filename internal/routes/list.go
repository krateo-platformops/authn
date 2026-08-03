package routes

import (
	"encoding/json"
	"net/http"

	"github.com/krateo-platformops/authn/internal/helpers/encode"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/rs/zerolog"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func List(rc *rest.Config) Route {
	return &listRoute{
		rc: rc,
	}
}

var _ Route = (*listRoute)(nil)

type listRoute struct {
	rc *rest.Config
}

func (r *listRoute) Name() string {
	return "list"
}

func (r *listRoute) Method() string {
	return http.MethodGet
}

func (r *listRoute) Pattern() string {
	return "/list"
}

func (r *listRoute) Handler() http.HandlerFunc {
	return http.HandlerFunc(func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context()).With().Logger()

		dyn, err := dynamic.NewForConfig(r.rc)
		if err != nil {
			log.Err(err).Msg("unable to create kubernetes dynamic config")
			encode.InternalError(wri, err)
			return
		}

		all, err := resolvers.ListOAuthConfigs(dyn)
		if err != nil {
			log.Err(err).Msg("unable to fetch oauth configurations")
			encode.InternalError(wri, err)
			return
		}

		res := authnTypesInfo{
			Oauth: all,
		}
		wri.WriteHeader(http.StatusOK)
		wri.Header().Set("Content-Type", "application/json")
		json.NewEncoder(wri).Encode(&res)
	})
}

type authnTypesInfo struct {
	Oauth []*resolvers.ConfigSpec `json:"data"`
}
