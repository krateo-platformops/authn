package ldap

import (
	"crypto/rsa"
	"errors"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"net/http"
	"os"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/decode"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

type LoginOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	// Audit records each verified identity\'s credential write (AUDIT-4). Nil records nothing.
	Audit         *auditlog.Recorder
	JwtDuration   time.Duration
	JwtPrivateKey *rsa.PrivateKey
	JwtKeyID      string
}

func Login(rc *rest.Config, opts LoginOptions) routes.Route {
	return &loginRoute{
		rc:            rc,
		gen:           opts.KubeconfigGenerator,
		audit:         opts.Audit,
		jwtDuration:   opts.JwtDuration,
		jwtPrivateKey: opts.JwtPrivateKey,
		jwtKeyID:      opts.JwtKeyID,
	}
}

const (
	Path = "/ldap/login"
)

var (
	_                     routes.Route = (*loginRoute)(nil)
	errNotFound                        = errors.New("no users found")
	errTooManyEntries                  = errors.New("too many entries found")
	errInvalidCredentials              = errors.New("invalid credentials")
)

// Causes of a failed LDAP login: the values of details.causes[0].reason
// (docs/api.md). They are added, never renamed.
const (
	// Refusals of the caller.
	CauseLDAPConfigNotFound status.CauseType = "LDAPConfigNotFound" // 404
	CauseAmbiguousUser      status.CauseType = "AmbiguousUser"      // 300
	CauseInvalidCredentials status.CauseType = "InvalidCredentials" // 403: unknown user or refused bind, answered alike

	// Failures of authn (500).
	CauseLDAPConfigLookupFailed status.CauseType = "LDAPConfigLookupFailed"
	CauseLDAPConfigInvalid      status.CauseType = "LDAPConfigInvalid"
	CauseLDAPUnavailable        status.CauseType = "LDAPUnavailable"
	CauseLDAPBindFailed         status.CauseType = "LDAPBindFailed"
	CauseLDAPSearchFailed       status.CauseType = "LDAPSearchFailed"
	CauseIssuanceFailed                          = status.CauseIssuanceFailed
)

type loginRoute struct {
	rc            *rest.Config
	gen           kubeconfig.Generator
	audit         *auditlog.Recorder
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
			err := status.BadRequest(status.CauseMissingConfigName, errors.New("LDAPConfig 'name' must be specified"))
			status.LogFailure(log, err).Msg("empty 'name' parameter in query string")
			encode.Failure(wri, status.FromError(err))
			return
		}

		var lo loginInfo
		err := decode.JSONBody(wri, req, &lo)
		if err != nil && !decode.IsEmptyBodyError(err) {
			err = status.BadRequest(status.CauseInvalidRequestBody, err)
			status.LogFailure(log, err).Msg("invalid request body")
			encode.Failure(wri, status.FromError(err))
			return
		}

		cfg, err := getConfig(r.rc, name)
		if err != nil {
			status.LogFailure(log, err).Str("name", name).Msg("unable to fetch ldap configuration")
			encode.Failure(wri, status.FromError(err))
			return
		}

		nfo, err := doLogin(lo.Username, lo.Password, cfg)
		if err != nil {
			status.LogFailure(log, err).Str("name", name).
				Str("dialURL", cfg.dialURL).
				Str("user", lo.Username).
				Msg("login with ldap server failed")
			encode.Failure(wri, status.FromError(err))
			return
		}

		issued, err := r.gen.Generate(storage.StrategyLDAP, nfo)
		r.audit.Issuance(req, auditlog.LoginAction(storage.StrategyLDAP), nfo, jwtutil.PrincipalHuman, issued, err)
		if err != nil {
			err = status.IssueFailure("clientconfig", err)
			status.LogFailure(log, err).Msg("kubeconfig creation failure")
			encode.Failure(wri, status.FromError(err))
			return
		}

		if err := encode.Success(wri, issued.Kubeconfig, &encode.Extras{
			UserInfo:      nfo,
			Strategy:      &encode.Strategy{Kind: string(storage.StrategyLDAP), Name: name},
			JwtDuration:   r.jwtDuration,
			JwtPrivateKey: r.jwtPrivateKey,
			JwtKeyID:      r.jwtKeyID,
			CertNotAfter:  issued.NotAfter,
			Principal:     jwtutil.PrincipalHuman,
		}); err != nil {
			// Success has already answered with IssuanceFailed.
			log.Err(err).Msg("access token creation failure")
		}
	}
}

type loginInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
