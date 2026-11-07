package oidc

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/codeexchange"
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
			err = status.Failed(CauseIssuanceFailed, fmt.Errorf("issuing clientconfig: %w", err))
			status.LogFailure(log, err).Msg("kubeconfig creation failure")
			encode.Failure(wri, status.FromError(err))
			return
		}

		if err := encode.Success(wri, dat, &encode.Extras{
			UserInfo:      nfo,
			Strategy:      &encode.Strategy{Kind: string(storage.StrategyOIDC), Name: req.URL.Query().Get("name")},
			JwtDuration:   r.jwtDuration,
			JwtPrivateKey: r.jwtPrivateKey,
			JwtKeyID:      r.jwtKeyID,
			CertNotAfter:  notAfter,
		}); err != nil {
			// Success has already answered with IssuanceFailed.
			log.Err(err).Msg("access token creation failure")
		}
	}
}

// authenticate runs the part of an OIDC login that /oidc/login and
// /oidc/stepup share: resolve the OIDCConfig, exchange the code, validate the
// ID token, enrich it through the RESTAction, and build the identity. On
// failure it has already written the response, and ok is false.
func authenticate(wri http.ResponseWriter, req *http.Request, base context.Context, rc *rest.Config, log zerolog.Logger) (cfg *oidcConfig, tok idToken, nfo userinfo.Info, ok bool) {
	name := req.URL.Query().Get("name")
	if len(name) == 0 {
		err := status.BadRequest(status.CauseMissingConfigName, errors.New("OIDCConfig 'name' must be specified"))
		status.LogFailure(log, err).Msg("empty 'name' parameter in query string")
		encode.Failure(wri, status.FromError(err))
		return nil, tok, nil, false
	}
	code := req.Header.Get(authCodeKey)
	if len(code) == 0 {
		err := status.BadRequest(status.CauseMissingAuthorizationCode, fmt.Errorf("the %s header must carry the authorization code", authCodeKey))
		status.LogFailure(log, err).Str("name", name).Msg("empty authorization code")
		encode.Failure(wri, status.FromError(err))
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
		status.LogFailure(log, err).Str("name", name).Msg("unable to fetch oidc configuration")
		encode.Failure(wri, status.FromError(err))
		return nil, tok, nil, false
	}

	log.Debug().Str("name", name).Msg("starting oidc login")
	tok, err = doLogin(callCtx, code, req.Header.Get(codeVerifierKey), cfg)
	if err != nil {
		// A public client's login without a PKCE verifier is a 400, a
		// rejected code or ID token a 403, each with its cause; anything else
		// is authn's (or its IdP's) failure, a 500.
		status.LogFailure(log, err).Str("name", name).Msg("unable to complete login")
		encode.Failure(wri, status.FromError(err))
		return nil, tok, nil, false
	}

	log.Debug().Str("name", name).Msg("resolving restaction")
	if cfg.RESTActionRef != nil {
		ref := cfg.RESTActionRef
		additionalFieldstoReplace, err := restaction.Resolve(callCtx, ref, tok.bearerToken)
		if err == nil {
			if _, kerr := checkKeys(additionalFieldstoReplace); kerr != nil {
				err = fmt.Errorf("the RESTAction's answer is unusable: %w", kerr)
			}
		}
		if err != nil {
			// The RESTAction may be written for the old shape, without a
			// ${ .token } header: only the legacy copy path serves it.
			log.Warn().Err(err).Str("name", name).Str("restaction", ref.Namespace+"/"+ref.Name).
				Msg("restaction fell back to the legacy copy path")
			additionalFieldstoReplace, err = restaction.LegacyResolve(callCtx, rc, ref, tok.email, tok.bearerToken)
			if err != nil {
				err = restaction.Failed(err)
				status.LogFailure(log, err).Str("name", name).Str("restaction", ref.Namespace+"/"+ref.Name).Msg("unable to resolve restaction, stopping")
				encode.Failure(wri, status.FromError(err))
				return nil, tok, nil, false
			}
		}
		log.Debug().Str("name", name).Msg("updating oidc idtoken")
		log.Debug().Str("name", name).Msgf("old idToken - name: %s - preferredUsername: %s - email: %s - groups: %s - avatarURL: %s", tok.name, tok.preferredUsername, tok.email, tok.groups, tok.avatarURL)
		log.Debug().Str("name", name).Msgf("values to replace: %s", additionalFieldstoReplace)
		tok, err = updateConfig(tok, additionalFieldstoReplace)
		if err != nil {
			err = status.Failed(CauseRESTActionFailed, fmt.Errorf("the RESTAction's answer is unusable: %w", err))
			status.LogFailure(log, err).Str("name", name).Msg("unable to parse updated idtoken from restaction")
			encode.Failure(wri, status.FromError(err))
			return nil, tok, nil, false
		}
		log.Debug().Str("name", name).Msgf("new idToken - name: %s - preferredUsername: %s - email: %s - groups: %s - avatarURL: %s", tok.name, tok.preferredUsername, tok.email, tok.groups, tok.avatarURL)
	}

	log.Debug().Str("name", name).Msg("validating idtoken")
	nfo = validate(tok)

	if err := checkAllowedGroups(cfg.AllowedGroups, nfo); err != nil {
		status.LogFailure(log, err).Str("name", name).Str("username", nfo.GetUserName()).Msg("login refused")
		encode.Failure(wri, status.FromError(err))
		return nil, tok, nil, false
	}
	return cfg, tok, nfo, true
}

// CauseGroupNotAllowed refuses a user the OIDCConfig's allowedGroups don't
// admit (403).
const CauseGroupNotAllowed status.CauseType = "GroupNotAllowed"

// Causes of a failed OIDC login besides the ID token's (idtoken.go), step-up's
// (stepup.go) and allowedGroups': the values of details.causes[0].reason
// (docs/api.md). They are added, never renamed.
const (
	// Refusals of the caller.
	CauseOIDCConfigNotFound status.CauseType = "OIDCConfigNotFound" // 404
	// CauseMissingCodeVerifier: the OIDCConfig is a public client (no
	// clientSecret) and the X-Code-Verifier header is missing or empty (400).
	CauseMissingCodeVerifier       status.CauseType = "MissingCodeVerifier"
	CauseAuthorizationCodeRejected                  = codeexchange.CauseAuthorizationCodeRejected

	// Failures of authn or its IdP (500).
	CauseOIDCConfigLookupFailed   status.CauseType = "OIDCConfigLookupFailed"
	CauseOIDCConfigInvalid        status.CauseType = "OIDCConfigInvalid"
	CauseOIDCDiscoveryFailed      status.CauseType = "OIDCDiscoveryFailed"
	CauseClientSecretLookupFailed status.CauseType = "ClientSecretLookupFailed"
	CauseTokenExchangeFailed                       = codeexchange.CauseTokenExchangeFailed
	CauseUserInfoFailed           status.CauseType = "UserInfoFailed"
	CauseRESTActionFailed                          = restaction.CauseRESTActionFailed
)

// checkAllowedGroups admits nfo when allowed is empty, or when nfo holds at
// least one allowed group. nfo's groups are final: reserved groups are
// already stripped, so krateo:loa:* can never admit anyone.
func checkAllowedGroups(allowed []string, nfo userinfo.Info) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, g := range nfo.GetGroups() {
		if slices.Contains(allowed, g) {
			return nil
		}
	}
	return status.Refused(CauseGroupNotAllowed, fmt.Errorf("user %q is in none of the groups this OIDCConfig admits", nfo.GetUserName()))
}

func validate(idToken idToken) userinfo.Info {
	exts := userinfo.Extensions{}
	exts.Add("name", idToken.name)
	exts.Add("avatarUrl", idToken.avatarURL)
	exts.Add("email", idToken.email)

	uid, _ := shortid.Generate()
	return userinfo.NewDefaultUser(kubeutil.MakeDNS1123Compatible(idToken.preferredUsername), uid, idToken.groups, exts)
}
