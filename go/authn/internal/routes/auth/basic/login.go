package basic

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"net/http"
	"os"
	"time"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/shortid"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/rs/zerolog"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

const (
	Path = "/basic/login"
)

// Causes of a failed basic login: the values of details.causes[0].reason
// (docs/api.md). They are added, never renamed.
const (
	// Refusals of the caller.
	CauseMissingCredentials status.CauseType = "MissingCredentials" // 401
	CauseInvalidCredentials status.CauseType = "InvalidCredentials" // 403: unknown user or wrong password, answered alike

	// Failures of authn (500).
	CauseUserLookupFailed      status.CauseType = "UserLookupFailed"
	CausePasswordSecretMissing status.CauseType = "PasswordSecretMissing"
	CausePasswordLookupFailed  status.CauseType = "PasswordLookupFailed"
	CauseIssuanceFailed                         = status.CauseIssuanceFailed
)

var (
	errMissingCredentials = errors.New("missing basic credentials")
	errInvalidCredentials = errors.New("invalid credentials")
)

// invalidCredentials refuses the caller with the one InvalidCredentials body;
// reason goes to the log only.
// comparePassword reports whether got is the stored password want, in time
// that depends on neither: both are hashed to SHA-256 first, so their
// lengths don't leak either, then compared with subtle.ConstantTimeCompare.
// The digest is not password storage: nothing hashed is kept or returned, it
// only gives both sides one length (CodeQL's go/weak-sensitive-data-hashing
// alerts on it were dismissed as false positives for that reason).
// A variable, so a test can count comparisons.
var comparePassword = func(got string, want []byte) bool {
	g, w := sha256.Sum256([]byte(got)), sha256.Sum256(want)
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

// DecoyKey is the key of the decoy Secret's value
// (helm/authn/templates/basic-decoy-secret.yaml).
const DecoyKey = "password"

// unknownUserPassword is what an unknown user's password is compared with when
// the decoy Secret can't be read. No caller's password can match it usefully,
// and neither can the decoy's value: the login is refused anyway.
var unknownUserPassword = []byte("authn: no such user")

func invalidCredentials(reason error) error {
	return status.RefusedPrivately(CauseInvalidCredentials, errInvalidCredentials, reason)
}

type LoginOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	// Audit records each verified identity\'s credential write (AUDIT-4). Nil records nothing.
	Audit         *auditlog.Recorder
	JwtDuration   time.Duration
	JwtPrivateKey *rsa.PrivateKey
	JwtKeyID      string
	// DecoySecret is read for an unknown user, so that a refusal costs the
	// Secret read a known user's does. Nil skips the read.
	DecoySecret *core.SecretKeySelector
}

func Login(rc *rest.Config, opts LoginOptions) routes.Route {
	return &loginRoute{
		rc:            rc,
		gen:           opts.KubeconfigGenerator,
		audit:         opts.Audit,
		jwtDuration:   opts.JwtDuration,
		jwtPrivateKey: opts.JwtPrivateKey,
		jwtKeyID:      opts.JwtKeyID,
		decoySecret:   opts.DecoySecret,
	}
}

var _ routes.Route = (*loginRoute)(nil)

type loginRoute struct {
	rc            *rest.Config
	gen           kubeconfig.Generator
	audit         *auditlog.Recorder
	jwtDuration   time.Duration
	jwtPrivateKey *rsa.PrivateKey
	jwtKeyID      string
	decoySecret   *core.SecretKeySelector
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
			encode.Failure(wri, status.New(http.StatusUnauthorized, errMissingCredentials).
				WithCause(CauseMissingCredentials, errMissingCredentials.Error()))
			return
		}

		log := zerolog.Ctx(req.Context()).With().
			Str("namespace", os.Getenv(util.NamespaceEnvVar)).
			Logger()

		user, err := r.validate(username, password)
		if err != nil {
			status.LogFailure(log, err).Msg("basic auth failed")
			encode.Failure(wri, status.FromError(err))
			return
		}
		log.Debug().Int("groups", len(user.GetGroups())).Msg("basic auth succeded")

		issued, err := r.gen.Generate(storage.StrategyBasic, user, kubeconfig.Logger(log))
		r.audit.Issuance(req, auditlog.LoginAction(storage.StrategyBasic), user, jwtutil.PrincipalHuman, issued, err)
		if err != nil {
			err = status.IssueFailure("clientconfig", err)
			status.LogFailure(log, err).Msg("kubeconfig creation failure")
			encode.Failure(wri, status.FromError(err))
			return
		}

		if req.URL.Query().Has("d") {
			encode.Attach(wri, username, issued.Kubeconfig)
			return
		}

		if err := encode.Success(wri, issued.Kubeconfig, &encode.Extras{
			UserInfo:      user,
			Strategy:      &encode.Strategy{Kind: string(storage.StrategyBasic)},
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

// validate checks the caller's credentials against its User and the Secret
// holding its password. An unknown user and a wrong password are the same
// refusal, InvalidCredentials (403), with the same body, so a caller can't
// probe which users exist; the real reason only reaches the log. A User or
// Secret authn can't read is authn's failure (500). No error names the user,
// the User or its Secret: the errors are logged, and no log line carries an
// identity (the apiserver's are wrapped by kerr).
func (r *loginRoute) validate(username, password string) (userinfo.Info, error) {
	if len(rest.IsValidPathSegmentName(username)) > 0 || username == "" {
		// No User can have this name; looking it up would fail client-side.
		return nil, invalidCredentials(errors.New("the username is not a valid User name"))
	}

	usr, err := resolvers.UserGet(r.rc, username)
	switch {
	case apierrors.IsNotFound(err):
		// Do the work a known user costs, a Secret read and a comparison, so
		// the time taken doesn't tell a caller which users exist.
		want, decoyErr := r.decoyPassword()
		_ = comparePassword(password, want)
		return nil, invalidCredentials(errors.Join(err, decoyErr))
	case err != nil:
		return nil, status.Failed(CauseUserLookupFailed, err)
	}

	ref := usr.Spec.PasswordRef
	if ref == nil {
		return nil, status.Failed(CausePasswordSecretMissing, errors.New("the User has no passwordRef"))
	}
	sec, err := secrets.Get(context.Background(), r.rc, ref)
	// The password Secret is often named after its user.
	err = kerr.Wrap("reading the User's password Secret", err)
	switch {
	case apierrors.IsNotFound(err):
		return nil, status.Failed(CausePasswordSecretMissing, err)
	case err != nil:
		return nil, status.Failed(CausePasswordLookupFailed, err)
	}
	pwd, ok := sec.Data[ref.Key]
	if !ok {
		return nil, status.Failed(CausePasswordSecretMissing, errors.New("the User's password Secret has no value under its passwordRef key"))
	}

	if !comparePassword(password, pwd) {
		return nil, invalidCredentials(errors.New("wrong password"))
	}

	exts := userinfo.Extensions{}
	exts.Add("name", usr.Spec.DisplayName)
	exts.Add("avatarUrl", usr.Spec.AvatarURL)

	uid, _ := shortid.Generate()
	nfo := userinfo.NewDefaultUser(usr.Name, uid, usr.Spec.Groups, exts)
	nfo.Subject = userinfo.Subject{Issuer: usr.Namespace, ID: usr.Name}
	return nfo, nil
}

// decoyPassword reads the decoy Secret and returns its value. A failed read is
// returned for the log only: the caller still gets the refusal an unknown user
// gets, because a different answer would say the name is unknown.
func (r *loginRoute) decoyPassword() ([]byte, error) {
	if r.decoySecret == nil {
		return unknownUserPassword, nil
	}
	sec, err := secrets.Get(context.Background(), r.rc, r.decoySecret)
	if err != nil {
		return unknownUserPassword, fmt.Errorf("reading the decoy Secret: %w", err)
	}
	pwd, ok := sec.Data[r.decoySecret.Key]
	if !ok {
		return unknownUserPassword, fmt.Errorf("the decoy Secret has no key %q", r.decoySecret.Key)
	}
	return pwd, nil
}
