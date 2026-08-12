package ldap

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/decode"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

type LoginOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	JwtDuration         time.Duration
	JwtPrivateKey       *rsa.PrivateKey
	JwtKeyID            string
}

func Login(rc *rest.Config, opts LoginOptions) routes.Route {
	return &loginRoute{
		rc:            rc,
		gen:           opts.KubeconfigGenerator,
		jwtDuration:   opts.JwtDuration,
		jwtPrivateKey: opts.JwtPrivateKey,
		jwtKeyID:      opts.JwtKeyID,
	}
}

const (
	Path = "/ldap/login"
)

var (
	_                 routes.Route = (*loginRoute)(nil)
	errNotFound                    = errors.New("no users found")
	errTooManyEntries              = errors.New("too many entries found")
)

type loginRoute struct {
	rc            *rest.Config
	gen           kubeconfig.Generator
	jwtDuration   time.Duration
	jwtPrivateKey *rsa.PrivateKey
	jwtKeyID      string
}

func (r *loginRoute) Name() string {
	return "ldap.login"
}

func (r *loginRoute) Pattern() string {
	return Path
}

func (r *loginRoute) Method() string {
	return http.MethodPost
}

//	curl -X POST "http://localhost:8080/ldap/login?name=forumsys" \
//	  -H 'Content-Type: application/json' \
//	  -d '{"username":"euler","password":"my_password"}'
func (r *loginRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context()).With().
			Str("namespace", os.Getenv(util.NamespaceEnvVar)).
			Logger()

		name := req.URL.Query().Get("name")
		if len(name) == 0 {
			err := fmt.Errorf("LDAPConfig 'name' must be specified")
			log.Err(err).Msgf("empty 'name' parameter in query string")
			encode.BadRequest(wri, err)
			return
		}

		var lo loginInfo
		err := decode.JSONBody(wri, req, &lo)
		if err != nil && !decode.IsEmptyBodyError(err) {
			log.Error().Msg(err.Error())
			encode.BadRequest(wri, err)
			return
		}

		cfg, err := getConfig(r.rc, name, lo.Username)
		if err != nil {
			log.Err(err).Str("name", name).Msg("unable to fetch ldap configuration")
			encode.ExpectationFailed(wri, err)
			return
		}

		nfo, err := doLogin(lo.Username, lo.Password, cfg)
		if err != nil {
			log.Err(err).Str("name", name).
				Str("dialURL", cfg.dialURL).
				Str("user", lo.Username).
				Msg("login with ldap server failed")
			code := http.StatusForbidden
			if errors.Is(err, errNotFound) {
				code = http.StatusNotFound
			} else if errors.Is(err, errTooManyEntries) {
				code = http.StatusMultipleChoices
			}
			encode.Failure(wri, status.New(code, err))
			return
		}

		dat, err := r.gen.Generate(nfo)
		if err != nil {
			log.Err(err).Msg("kubeconfig creation failure")
			encode.InternalError(wri, err)
			return
		}

		encode.Success(wri, dat, &encode.Extras{
			UserInfo:      nfo,
			JwtDuration:   r.jwtDuration,
			JwtPrivateKey: r.jwtPrivateKey,
			JwtKeyID:      r.jwtKeyID,
		})
	}
}

type loginInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
