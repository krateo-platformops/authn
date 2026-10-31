package oidc

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/shortid"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/kubeutil"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

const (
	Path = "/oidc/login"

	authCodeKey = "X-Auth-Code"
	// codeVerifierKey carries the PKCE code_verifier (RFC 7636) of the
	// authorization request whose code is in X-Auth-Code. Optional.
	codeVerifierKey = "X-Code-Verifier"
)

type LoginOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	JwtDuration         time.Duration
	JwtPrivateKey       *rsa.PrivateKey
	JwtKeyID            string
}

func Login(ctx context.Context, rc *rest.Config, opts LoginOptions) routes.Route {
	return &loginRoute{
		rc: rc, ctx: ctx,
		gen:           opts.KubeconfigGenerator,
		jwtDuration:   opts.JwtDuration,
		jwtPrivateKey: opts.JwtPrivateKey,
		jwtKeyID:      opts.JwtKeyID,
	}
}

var _ routes.Route = (*loginRoute)(nil)

type loginRoute struct {
	rc            *rest.Config
	gen           kubeconfig.Generator
	ctx           context.Context
	jwtDuration   time.Duration
	jwtPrivateKey *rsa.PrivateKey
	jwtKeyID      string
}

func (r *loginRoute) Name() string {
	return "oidc.login"
}

func (r *loginRoute) Pattern() string {
	return Path
}

func (r *loginRoute) Method() string {
	return http.MethodGet
}

func (r *loginRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context()).With().
			Str("namespace", os.Getenv(util.NamespaceEnvVar)).
			Logger()

		_, _, nfo, ok := authenticate(wri, req, r.ctx, r.rc, log)
		if !ok {
			return
		}

		log.Debug().Msg("generating secret from oidc idtoken")
		dat, notAfter, err := r.gen.Generate(storage.StrategyOIDC, nfo)
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
			CertNotAfter:  notAfter,
		})
	}
}

// authenticate runs the part of an OIDC login that /oidc/login and
// /oidc/stepup share: resolve the OIDCConfig, exchange the code, validate the
// ID token, enrich it through the RESTAction, and build the identity. On
// failure it has already written the response, and ok is false.
func authenticate(wri http.ResponseWriter, req *http.Request, base context.Context, rc *rest.Config, log zerolog.Logger) (cfg *oidcConfig, tok idToken, nfo userinfo.Info, ok bool) {
	name := req.URL.Query().Get("name")
	if len(name) == 0 {
		err := fmt.Errorf("OIDCConfig 'name' must be specified")
		log.Err(err).Msgf("empty 'name' parameter in query string")
		encode.BadRequest(wri, err)
		return nil, tok, nil, false
	}

	// Bridge the inbound request span (req.Context()) with the long-lived
	// values (accessToken/username/snowplowURL) carried by base so the
	// outbound OIDC-discovery / token / userinfo / snowplow hops are both
	// traced and authenticated. With tracing OFF this just returns
	// req.Context() with the same values copied — behaviourally identical.
	callCtx := restaction.MergeRequestContext(req.Context(), base)

	cfg, err := getConfig(callCtx, rc, name)
	if err != nil {
		log.Err(err).Str("name", name).Msg("unable to fetch oidc configuration")
		if errors.As(err, new(status.CauseError)) {
			encode.Failure(wri, status.FromError(err))
		} else {
			encode.ExpectationFailed(wri, err)
		}
		return nil, tok, nil, false
	}

	log.Debug().Str("name", name).Msg("starting oidc login")
	tok, err = doLogin(callCtx, req.Header.Get(authCodeKey), req.Header.Get(codeVerifierKey), cfg)
	if err != nil {
		// A rejected ID token is a 403 with its cause; anything else is
		// authn's failure, a 500.
		log.Err(err).Str("name", name).Msg("unable to complete login")
		encode.Failure(wri, status.FromError(err))
		return nil, tok, nil, false
	}

	log.Debug().Str("name", name).Msg("resolving restaction")
	if cfg.RESTActionRef != nil {
		additionalFieldstoReplace, err := restaction.Resolve(callCtx, rc, cfg.RESTActionRef, tok.email, tok.bearerToken)
		keysOK, errr := checkKeys(additionalFieldstoReplace)
		if err != nil || !keysOK || errr != nil {
			if errr != nil {
				log.Err(err).Str("name", name).Msgf("restaction parsing has found the following error: %v", errr)
			}
			log.Err(err).Str("name", name).Msg("unable to resolve restaction, retrying with legacy resolve (copy)")
			additionalFieldstoReplace, err = restaction.LegacyResolve(callCtx, rc, cfg.RESTActionRef, tok.email, tok.bearerToken)
			if err != nil {
				log.Err(err).Str("name", name).Msg("unable to resolve restaction, stopping")
				encode.InternalError(wri, err)
				return nil, tok, nil, false
			}
		}
		log.Debug().Str("name", name).Msg("updating oidc idtoken")
		log.Debug().Str("name", name).Msgf("old idToken - name: %s - preferredUsername: %s - email: %s - groups: %s - avatarURL: %s", tok.name, tok.preferredUsername, tok.email, tok.groups, tok.avatarURL)
		log.Debug().Str("name", name).Msgf("values to replace: %s", additionalFieldstoReplace)
		tok, err = updateConfig(tok, additionalFieldstoReplace)
		if err != nil {
			log.Err(err).Str("name", name).Msg("unable to parse updated idtoken from restaction")
			encode.InternalError(wri, err)
			return nil, tok, nil, false
		}
		log.Debug().Str("name", name).Msgf("new idToken - name: %s - preferredUsername: %s - email: %s - groups: %s - avatarURL: %s", tok.name, tok.preferredUsername, tok.email, tok.groups, tok.avatarURL)
	}

	log.Debug().Str("name", name).Msg("validating idtoken")
	nfo, err = validate(tok)
	if err != nil {
		log.Err(err).Str("name", name).
			Str("tokenURL", cfg.TokenURL).
			Msg("user info default user error for oidc")
		encode.Forbidden(wri, err)
		return nil, tok, nil, false
	}
	return cfg, tok, nfo, true
}

func validate(idToken idToken) (userinfo.Info, error) {
	exts := userinfo.Extensions{}
	exts.Add("name", idToken.name)
	exts.Add("avatarUrl", idToken.avatarURL)
	exts.Add("email", idToken.email)

	uid, _ := shortid.Generate()
	nfo := userinfo.NewDefaultUser(kubeutil.MakeDNS1123Compatible(idToken.preferredUsername), uid, idToken.groups, exts)
	return nfo, nil
}
