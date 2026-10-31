package oidc

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	oidcv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oidc/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

// StepUpPath is the step-up login (#49). It takes the same input as
// /oidc/login, from an authorization request that asked for a higher
// assurance level (acr_values). If the ID token proves that level, and the
// authentication is recent, it issues a short-lived credential carrying the
// group krateo:loa:2. The user's session credential is never touched.
const StepUpPath = "/oidc/stepup"

// StepUpLevel is the level of assurance a step-up login grants.
const StepUpLevel = 2

const (
	DefaultStepUpMaxAge = 5 * time.Minute
	DefaultStepUpTTL    = 15 * time.Minute
	// MinStepUpTTL is the Kubernetes CSR API's minimum expirationSeconds.
	MinStepUpTTL = 10 * time.Minute
)

// Step-up causes, in the same contract as the login causes (docs/api.md).
const (
	// Refusals (403).
	CauseStepUpNotEnabled      status.CauseType = "StepUpNotEnabled"
	CauseInsufficientAssurance status.CauseType = "InsufficientAssurance"
	CauseStaleAuthentication   status.CauseType = "StaleAuthentication"

	// Failures of authn or its configuration (500).
	CauseStepUpMisconfigured status.CauseType = "StepUpMisconfigured"
	CauseIssuanceFailed                       = status.CauseIssuanceFailed
)

type stepUpConfig struct {
	acrValues []string
	maxAge    time.Duration
	ttl       time.Duration
}

// resolveStepUp applies the defaults to an OIDCConfig's spec.stepUp. nil
// means step-up is not enabled.
func resolveStepUp(spec *oidcv1alpha1.OIDCStepUp) *stepUpConfig {
	if spec == nil {
		return nil
	}
	cfg := &stepUpConfig{acrValues: spec.AcrValues, maxAge: DefaultStepUpMaxAge, ttl: DefaultStepUpTTL}
	if spec.MaxAge != nil {
		cfg.maxAge = spec.MaxAge.Duration
	}
	if spec.TTL != nil {
		cfg.ttl = spec.TTL.Duration
	}
	return cfg
}

// validate refuses a spec.stepUp that can never grant a step-up correctly.
// An acr value must be non-empty (an empty one would match an ID token with
// no acr) and contain no whitespace (acr_values is space-separated).
func (cfg *stepUpConfig) validate() error {
	if len(cfg.acrValues) == 0 || cfg.maxAge <= 0 || cfg.ttl < MinStepUpTTL {
		return status.Failed(CauseStepUpMisconfigured, fmt.Errorf(
			"spec.stepUp needs acrValues, a positive maxAge and a ttl of at least %s (got %d acrValues, maxAge %s, ttl %s)",
			MinStepUpTTL, len(cfg.acrValues), cfg.maxAge, cfg.ttl))
	}
	for _, v := range cfg.acrValues {
		if v == "" || strings.ContainsFunc(v, unicode.IsSpace) {
			return status.Failed(CauseStepUpMisconfigured, fmt.Errorf(
				"spec.stepUp.acrValues has %q: an acr value must be non-empty and contain no whitespace", v))
		}
	}
	return nil
}

// checkStepUp decides whether a validated ID token proves a step-up:
// - step-up is enabled for the provider;
// - its acr is one of the configured values;
// - it authenticated within maxAge.
func checkStepUp(cfg *stepUpConfig, tok idToken, now time.Time) error {
	if cfg == nil {
		return status.Refused(CauseStepUpNotEnabled, errors.New("step-up is not enabled for this OIDCConfig (spec.stepUp)"))
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if !slices.Contains(cfg.acrValues, tok.acr) {
		return status.Refused(CauseInsufficientAssurance, fmt.Errorf("ID token acr %q is not one of %q", tok.acr, cfg.acrValues))
	}
	if tok.authTime.IsZero() {
		return status.Refused(CauseStaleAuthentication, errors.New("ID token has no auth_time, so the authentication's age is unknown"))
	}
	if age := now.Sub(tok.authTime); age > cfg.maxAge {
		return status.Refused(CauseStaleAuthentication, fmt.Errorf("authenticated %s ago, more than the %s step-up allows", age.Truncate(time.Second), cfg.maxAge))
	}
	return nil
}

// The /strategies extensions that tell the portal how to ask for a step-up
// with an OIDCConfig. They're set only when spec.stepUp is set and valid.
const (
	// ExtStepUpAuthCodeURL is the complete step-up authorization request:
	// the entry's authCodeURL with acr_values and max_age set. The portal
	// redirects to it as is.
	ExtStepUpAuthCodeURL = "stepUpAuthCodeURL"
	// ExtStepUpPath is where to POST the authorization code: /oidc/stepup.
	ExtStepUpPath = "stepUpPath"
	// ExtStepUpAcrValues is the authorization request's acr_values: the
	// configured acr values, space-separated.
	ExtStepUpAcrValues = "stepUpAcrValues"
	// ExtStepUpMaxAge is the authorization request's max_age, in seconds.
	// It makes the IdP re-authenticate a user whose last authentication is
	// older than authn accepts, instead of authn refusing it as
	// StaleAuthentication.
	ExtStepUpMaxAge = "stepUpMaxAge"
)

// StepUpExtensions returns the /strategies extensions for an OIDCConfig's
// spec.stepUp, given the entry's login authCodeURL: nil when step-up isn't
// enabled, an error when it's misconfigured (a step-up would answer
// StepUpMisconfigured) or authCodeURL can't be parsed.
func StepUpExtensions(spec *oidcv1alpha1.OIDCStepUp, authCodeURL string) (map[string]string, error) {
	cfg := resolveStepUp(spec)
	if cfg == nil {
		return nil, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	acrValues := strings.Join(cfg.acrValues, " ")
	maxAge := strconv.FormatInt(int64(cfg.maxAge/time.Second), 10)

	u, err := url.Parse(authCodeURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("authCodeURL %q is not an absolute URL: %v", authCodeURL, err)
	}
	q := u.Query()
	q.Set("acr_values", acrValues)
	q.Set("max_age", maxAge)
	u.RawQuery = q.Encode()

	return map[string]string{
		ExtStepUpAuthCodeURL: u.String(),
		ExtStepUpPath:        StepUpPath,
		ExtStepUpAcrValues:   acrValues,
		ExtStepUpMaxAge:      maxAge,
	}, nil
}

type StepUpOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	JwtPrivateKey       *rsa.PrivateKey
	JwtKeyID            string
}

func StepUp(ctx context.Context, rc *rest.Config, opts StepUpOptions) routes.Route {
	return &stepUpRoute{
		rc: rc, ctx: ctx,
		gen:           opts.KubeconfigGenerator,
		jwtPrivateKey: opts.JwtPrivateKey,
		jwtKeyID:      opts.JwtKeyID,
	}
}

var _ routes.Route = (*stepUpRoute)(nil)

type stepUpRoute struct {
	rc            *rest.Config
	ctx           context.Context
	gen           kubeconfig.Generator
	jwtPrivateKey *rsa.PrivateKey
	jwtKeyID      string
}

func (r *stepUpRoute) Name() string    { return "oidc.stepup" }
func (r *stepUpRoute) Pattern() string { return StepUpPath }
func (r *stepUpRoute) Method() string  { return http.MethodPost }

func (r *stepUpRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context()).With().
			Str("namespace", os.Getenv(util.NamespaceEnvVar)).
			Logger()

		cfg, tok, nfo, ok := authenticate(wri, req, r.ctx, r.rc, log)
		if !ok {
			return
		}

		if err := checkStepUp(cfg.StepUp, tok, time.Now()); err != nil {
			log.Err(err).Str("username", nfo.GetUserName()).Msg("step-up refused")
			encode.Failure(wri, status.FromError(err))
			return
		}

		up := userinfo.NewStepUpUser(nfo, StepUpLevel)
		notAfter, err := r.gen.GenerateStepUp(storage.StrategyOIDC, up, cfg.StepUp.ttl)
		if err != nil {
			log.Err(err).Str("username", up.GetUserName()).Msg("step-up credential creation failure")
			encode.Failure(wri, status.FromError(status.Failed(CauseIssuanceFailed, fmt.Errorf("issuing step-up credential: %w", err))))
			return
		}

		// The token carries krateo:loa:2 in its groups, which is how snowplow
		// selects the step-up credential. It lives no longer than that
		// credential. No kubeconfig is returned: the private key stays in the
		// Secret.
		err = encode.Success(wri, nil, &encode.Extras{
			UserInfo:      up,
			JwtDuration:   cfg.StepUp.ttl,
			JwtPrivateKey: r.jwtPrivateKey,
			JwtKeyID:      r.jwtKeyID,
			CertNotAfter:  notAfter,
		})
		if err != nil {
			// Success has already answered with IssuanceFailed.
			log.Err(err).Msg("step-up access token creation failure")
			return
		}
		log.Info().Str("username", up.GetUserName()).Time("notAfter", notAfter).Msg("step-up granted")
	}
}
