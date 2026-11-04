package oauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
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
	"github.com/krateo-platformops/authn/internal/telemetry"
	"github.com/krateo-platformops/plumbing/kubeutil"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"k8s.io/client-go/rest"
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

const (
	Path        = "/oauth/login"
	authCodeKey = "X-Auth-Code"
	// codeVerifierKey carries the PKCE code_verifier (RFC 7636) of the
	// authorization request whose code is in X-Auth-Code. Optional, as on
	// /oidc/login: the client that added the code_challenge sends it.
	codeVerifierKey = "X-Code-Verifier"
)

var _ routes.Route = (*loginRoute)(nil)

// Causes of a failed OAuth login: the values of details.causes[0].reason
// (docs/api.md). They are added, never renamed.
const (
	// Refusals of the caller.
	CauseOAuthConfigNotFound       status.CauseType = "OAuthConfigNotFound" // 404
	CauseAuthorizationCodeRejected                  = codeexchange.CauseAuthorizationCodeRejected

	// Failures of authn or its IdP (500).
	CauseOAuthConfigLookupFailed  status.CauseType = "OAuthConfigLookupFailed"
	CauseClientSecretLookupFailed status.CauseType = "ClientSecretLookupFailed"
	CauseTokenExchangeFailed                       = codeexchange.CauseTokenExchangeFailed
	CauseRESTActionFailed                          = restaction.CauseRESTActionFailed
	CauseIssuanceFailed                            = status.CauseIssuanceFailed
)

type loginRoute struct {
	rc            *rest.Config
	gen           kubeconfig.Generator
	ctx           context.Context
	jwtDuration   time.Duration
	jwtPrivateKey *rsa.PrivateKey
	jwtKeyID      string
}

func (r *loginRoute) Name() string {
	return "oauth.login"
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

		name := req.URL.Query().Get("name")
		if len(name) == 0 {
			err := status.BadRequest(status.CauseMissingConfigName, errors.New("OAuthConfig 'name' must be specified"))
			status.LogFailure(log, err).Msg("empty 'name' parameter in query string")
			encode.Failure(wri, status.FromError(err))
			return
		}

		code := req.Header.Get(authCodeKey)
		if len(code) == 0 {
			err := status.BadRequest(status.CauseMissingAuthorizationCode, fmt.Errorf("the %s header must carry the authorization code", authCodeKey))
			status.LogFailure(log, err).Str("name", name).Msg("empty authorization code")
			encode.Failure(wri, status.FromError(err))
			return
		}

		oc, restactionRef, err := getConfig(r.rc, name)
		if err != nil {
			status.LogFailure(log, err).Str("name", name).Msg("unable to fetch oauth2 configuration")
			encode.Failure(wri, status.FromError(err))
			return
		}

		// Bridge the inbound request span (req.Context()) with the long-lived
		// values (accessToken/username/snowplowURL) carried by r.ctx so the
		// outbound snowplow hop is both traced and authenticated. With tracing
		// OFF this is behaviourally identical to using req.Context().
		callCtx := restaction.MergeRequestContext(req.Context(), r.ctx)

		// use code to get token. Use the request-scoped context (not a fresh
		// Background) so the token-exchange hop is traced and cancelled with the
		// inbound request; inject the instrumented HTTP client when tracing is on.
		exchangeCtx := context.WithValue(callCtx, oauth2.HTTPClient, telemetry.HTTPClient())
		var exchangeOpts []oauth2.AuthCodeOption
		if verifier := req.Header.Get(codeVerifierKey); verifier != "" {
			exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(verifier))
		}
		tok, err := oc.Exchange(exchangeCtx, code, exchangeOpts...)
		if err != nil {
			err = classifyExchange(err)
			status.LogFailure(log, err).Str("name", name).Msg("unable to exchange the authorization code")
			encode.Failure(wri, status.FromError(err))
			return
		}

		userinfo := userInfo{}
		log.Debug().Str("name", name).Msg("resolving restaction")
		if restactionRef != nil {
			// RFC 6749 §7.1: the token type is case-insensitive.
			if !strings.EqualFold(tok.TokenType, "bearer") {
				err := codeexchange.Failed(fmt.Errorf("oauth2 token is not type bearer: %s", tok.TokenType))
				status.LogFailure(log, err).Str("name", name).Msg("error while resolving restaction")
				encode.Failure(wri, status.FromError(err))
				return
			}
			ref := restactionRef
			additionalFieldstoReplace, err := restaction.Resolve(callCtx, ref, tok.AccessToken)
			if err == nil {
				if v, ok := additionalFieldstoReplace["name"].(string); !ok || v == "" {
					err = errors.New("the RESTAction's answer has no name")
				}
			}
			if err != nil {
				err = restaction.Failed(err)
				status.LogFailure(log, err).Str("name", name).Str("restaction", ref.Namespace+"/"+ref.Name).Msg("unable to resolve restaction")
				encode.Failure(wri, status.FromError(err))
				return
			}
			log.Debug().Str("name", name).Msgf("values to replace: %s", additionalFieldstoReplace)
			userinfo, err = updateConfig(userinfo, additionalFieldstoReplace)
			if err != nil {
				err = status.Failed(CauseRESTActionFailed, fmt.Errorf("the RESTAction's answer is unusable: %w", err))
				status.LogFailure(log, err).Str("name", name).Msg("unable to parse updated config from restaction")
				encode.Failure(wri, status.FromError(err))
				return
			}
			log.Debug().Str("name", name).Msgf("new idToken - name: %s - preferredUsername: %s - email: %s - groups: %s - avatarURL: %s", userinfo.name, userinfo.preferredUsername, userinfo.email, userinfo.groups, userinfo.avatarURL)
		}

		user := r.validate(userinfo)
		log.Info().
			Str("user", user.GetUserName()).
			Strs("groups", user.GetGroups()).
			Msg("user info successfully fetched")

		dat, notAfter, err := r.gen.Generate(storage.StrategyOAuth, user)
		if err != nil {
			err = status.Failed(CauseIssuanceFailed, fmt.Errorf("issuing clientconfig: %w", err))
			status.LogFailure(log, err).Msg("kubeconfig creation failure")
			encode.Failure(wri, status.FromError(err))
			return
		}

		if err := encode.Success(wri, dat, &encode.Extras{
			UserInfo:      user,
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

func (r *loginRoute) validate(user userInfo) userinfo.Info {
	exts := userinfo.Extensions{}
	exts.Add("name", user.name)
	exts.Add("email", user.email)
	exts.Add("avatarUrl", user.avatarURL)

	uid, _ := shortid.Generate()
	return userinfo.NewDefaultUser(kubeutil.MakeDNS1123Compatible(user.preferredUsername), uid, user.groups, exts)
}

// classifyExchange gives a failed code exchange its cause: the token
// endpoint's error answer is a refusal of the code or a failure
// (codeexchange.Refusal); no answer at all is a failure.
func classifyExchange(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) && re.Response != nil {
		return codeexchange.Refusal(re.Response.StatusCode, re.ErrorCode, err)
	}
	return codeexchange.Failed(err)
}
