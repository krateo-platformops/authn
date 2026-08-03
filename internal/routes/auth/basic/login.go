package basic

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/shortid"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

const (
	Path = "/basic/login"
)

type LoginOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	JwtDuration         time.Duration
	JwtSingKey          string
}

func Login(rc *rest.Config, opts LoginOptions) routes.Route {
	return &loginRoute{
		rc:          rc,
		gen:         opts.KubeconfigGenerator,
		jwtDuration: opts.JwtDuration,
		jwtSignKey:  opts.JwtSingKey,
	}
}

var _ routes.Route = (*loginRoute)(nil)

type loginRoute struct {
	rc          *rest.Config
	gen         kubeconfig.Generator
	jwtDuration time.Duration
	jwtSignKey  string
}

func (r *loginRoute) Name() string {
	return "basic"
}

func (r *loginRoute) Pattern() string {
	return Path
}

func (r *loginRoute) Method() string {
	return http.MethodGet
}

func (r *loginRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		username, password, ok := req.BasicAuth()
		if !ok {
			wri.Header().Set("WWW-Authenticate", `Basic realm="krateo", charset="UTF-8"`)
			http.Error(wri, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log := zerolog.Ctx(req.Context()).With().
			Str("namespace", os.Getenv(util.NamespaceEnvVar)).
			Logger()

		user, err := r.validate(username, password)
		if err != nil {
			log.Err(err).Msg("basic auth failed")
			encode.Forbidden(wri, err)
			return
		}
		log.Debug().
			Str("username", user.GetUserName()).
			Str("groups", strings.Join(user.GetGroups(), ",")).
			Msg("basic auth succeded")

		dat, err := r.gen.Generate(user)
		if err != nil {
			log.Err(err).Msg("kubeconfig creation failure")
			encode.InternalError(wri, err)
			return
		}

		if req.URL.Query().Has("d") {
			encode.Attach(wri, username, dat)
			return
		}

		encode.Success(wri, dat, &encode.Extras{
			UserInfo:    user,
			JwtDuration: r.jwtDuration,
			JwtSingKey:  r.jwtSignKey,
		})
	}
}

func (r *loginRoute) validate(username, password string) (userinfo.Info, error) {
	usr, err := resolvers.UserGet(r.rc, username)
	if err != nil {
		return nil, err
	}

	sec, err := secrets.Get(context.Background(), r.rc, usr.Spec.PasswordRef)
	if err != nil {
		return nil, err
	}
	pwd, ok := sec.Data[usr.Spec.PasswordRef.Key]
	if !ok {
		return nil, fmt.Errorf("password for user '%s' not found", username)
	}

	if password != string(pwd) {
		return nil, fmt.Errorf("invalid credentials")
	}

	exts := userinfo.Extensions{}
	exts.Add("name", usr.Spec.DisplayName)
	exts.Add("avatarUrl", usr.Spec.AvatarURL)

	uid, _ := shortid.Generate()
	nfo := userinfo.NewDefaultUser(usr.Name, uid, usr.Spec.Groups, exts)
	return nfo, nil
}
