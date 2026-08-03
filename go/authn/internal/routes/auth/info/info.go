package info

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/krateo-platformops/authn/internal/helpers/encode"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

const (
	Path = "/info"
)

func Info(rc *rest.Config) routes.Route {
	return &infoRoute{
		store: storage.Default(rc),
	}
}

var _ routes.Route = (*infoRoute)(nil)

type infoRoute struct {
	store storage.AuthInfoStorage
}

func (r *infoRoute) Name() string {
	return "info"
}

func (r *infoRoute) Pattern() string {
	return Path
}

func (r *infoRoute) Method() string {
	return http.MethodGet
}

func (r *infoRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context()).With().
			Str("namespace", os.Getenv(util.NamespaceEnvVar)).
			Logger()

		qs := req.URL.Query()
		name := qs.Get("name")
		if len(name) == 0 {
			err := fmt.Errorf("missing 'name' param")
			log.Err(err).Msg("required query string param non found")
			encode.BadRequest(wri, err)
			return
		}

		nfo, err := r.store.Get(name)
		if err != nil {
			log.Err(err).
				Str("name", name).
				Msg("unable to resolve authinfo secret")
			encode.InternalError(wri, err)
			return
		}

		dat, err := json.Marshal(nfo)
		if err != nil {
			log.Err(err).
				Str("name", name).
				Msg("unable to encode authinfo")
			encode.InternalError(wri, err)
			return
		}

		encode.Success(wri, dat, nil)
	}
}
