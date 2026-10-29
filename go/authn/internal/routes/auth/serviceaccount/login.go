// Package serviceaccount implements the Kubernetes intra-service auth login strategy: a
// backend service presents its own (audience-bound) ServiceAccount token, authn validates
// it via the Kubernetes TokenReview API, maps the authenticated ServiceAccount to a
// serviceaccount.authn.krateo.io/ServiceAccount mapping (the allowlist), and issues the same
// JWT + clientconfig the other strategies do. See docs/design/kubernetes-intra-service-auth.md.
package serviceaccount

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/shortid"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/rs/zerolog"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	Path = "/serviceaccount/login"
	// DefaultAudience the projected SA token must be bound to.
	DefaultAudience = "authn"
)

type LoginOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	JwtDuration         time.Duration
	JwtPrivateKey       *rsa.PrivateKey
	JwtKeyID            string
	// Audience the projected SA token must carry (enforced via TokenReview); defaults to
	// DefaultAudience. Binding the audience prevents replay of tokens minted for the
	// apiserver or another service.
	Audience string
}

func Login(rc *rest.Config, opts LoginOptions) routes.Route {
	aud := opts.Audience
	if aud == "" {
		aud = DefaultAudience
	}
	return &loginRoute{
		rc:            rc,
		gen:           opts.KubeconfigGenerator,
		jwtDuration:   opts.JwtDuration,
		jwtPrivateKey: opts.JwtPrivateKey,
		jwtKeyID:      opts.JwtKeyID,
		audience:      aud,
	}
}

var _ routes.Route = (*loginRoute)(nil)

type loginRoute struct {
	rc            *rest.Config
	gen           kubeconfig.Generator
	jwtDuration   time.Duration
	jwtPrivateKey *rsa.PrivateKey
	jwtKeyID      string
	audience      string
}

func (r *loginRoute) Name() string    { return "serviceaccount" }
func (r *loginRoute) Pattern() string { return Path }
func (r *loginRoute) Method() string  { return http.MethodPost }

func (r *loginRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context())

		token, ok := bearerToken(req)
		if !ok {
			wri.Header().Set("WWW-Authenticate", `Bearer realm="krateo"`)
			encode.Failure(wri, status.New(http.StatusUnauthorized, errMissingBearer).
				WithCause(CauseMissingBearer, errMissingBearer.Error()))
			return
		}

		user, err := r.validate(req.Context(), token)
		if err != nil {
			log.Err(err).Msg("serviceaccount auth failed")
			encode.Failure(wri, failureStatus(err))
			return
		}
		log.Debug().
			Str("username", user.GetUserName()).
			Str("groups", strings.Join(user.GetGroups(), ",")).
			Msg("serviceaccount auth succeeded")

		// Generate mints the client certificate and persists the identity's
		// <username>-clientconfig Secret, which in-cluster consumers (snowplow,
		// plumbing endpoints, bff) read. The kubeconfig it returns is NOT put in
		// the response: it carries client-key-data, a private key, and no
		// service caller reads it; they all use accessToken alone. Keeping it
		// out of the body means printing or logging a successful response can't
		// leak the key (#36).
		_, notAfter, err := r.gen.Generate(storage.StrategyServiceAccount, user)
		if err != nil {
			log.Err(err).Msg("kubeconfig creation failure")
			encode.Failure(wri, failureStatus(authnFailure(CauseIssuanceFailed, fmt.Errorf("issuing clientconfig: %w", err))))
			return
		}

		err = encode.Success(wri, nil, &encode.Extras{
			UserInfo:      user,
			JwtDuration:   r.jwtDuration,
			JwtPrivateKey: r.jwtPrivateKey,
			JwtKeyID:      r.jwtKeyID,
			CertNotAfter:  notAfter,
		})
		if err != nil {
			// Success wrote nothing, so the caller still gets an answer.
			log.Err(err).Msg("access token creation failure")
			encode.Failure(wri, failureStatus(authnFailure(CauseIssuanceFailed, fmt.Errorf("issuing access token: %w", err))))
		}
	}
}

// validate verifies the SA token via the Kubernetes TokenReview API (audience-bound), maps
// the authenticated ServiceAccount to a ServiceAccount mapping (the allowlist), and builds
// the issued identity (username = mapping name, groups = mapping spec.groups).
func (r *loginRoute) validate(ctx context.Context, token string) (userinfo.Info, error) {
	clientset, err := kubernetes.NewForConfig(r.rc)
	if err != nil {
		return nil, authnFailure(CauseTokenReviewFailed, fmt.Errorf("token review: building the client: %w", err))
	}

	tr := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{r.audience},
		},
	}
	tr, err = clientset.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, authnFailure(CauseTokenReviewFailed, fmt.Errorf("token review: %w", err))
	}
	if !tr.Status.Authenticated {
		// status.error is the apiserver's verdict on the caller's token
		// (invalid signature, expired, deleted ServiceAccount): a refusal of
		// the caller, not a failure of authn.
		msg := "token not authenticated"
		if tr.Status.Error != "" {
			msg += ": " + tr.Status.Error
		}
		return nil, rejected(CauseTokenNotAuthenticated, errors.New(msg))
	}
	if !containsAudience(tr.Status.Audiences, r.audience) {
		return nil, rejected(CauseAudienceMismatch, fmt.Errorf("token audience mismatch (require %q)", r.audience))
	}

	saNamespace, saName, err := parseServiceAccountUsername(tr.Status.User.Username)
	if err != nil {
		return nil, rejected(CauseNotAServiceAccount, err)
	}

	mapping, err := resolvers.ServiceAccountForSA(r.rc, saNamespace, saName)
	switch {
	case errors.Is(err, resolvers.ErrNoMapping):
		return nil, rejected(CauseNoMapping, err)
	case errors.Is(err, resolvers.ErrAmbiguousMapping):
		return nil, rejected(CauseAmbiguousMapping, err)
	case err != nil:
		return nil, authnFailure(CauseMappingLookupFailed, err)
	}

	exts := userinfo.Extensions{}
	exts.Add("name", mapping.Spec.DisplayName)

	uid, _ := shortid.Generate()
	return userinfo.NewDefaultUser(mapping.Name, uid, mapping.Spec.Groups, exts), nil
}

func bearerToken(req *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := req.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

func containsAudience(auds []string, want string) bool {
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}

// parseServiceAccountUsername parses a TokenReview username of the form
// "system:serviceaccount:<namespace>:<name>".
func parseServiceAccountUsername(u string) (namespace, name string, err error) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(u, prefix) {
		return "", "", fmt.Errorf("not a service account token (username %q)", u)
	}
	parts := strings.SplitN(strings.TrimPrefix(u, prefix), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("malformed service account username %q", u)
	}
	return parts[0], parts[1], nil
}

// Causes are the machine-readable reasons a serviceaccount login fails,
// returned in the Status body's details.causes[].reason. They are part of the
// API contract (docs/api.md): values are added, never renamed.
//
// The status class carries the blame. A 401/403 means authn refused the
// caller: retrying unchanged will fail again, and the fix is on the caller's
// side (its token, audience or mapping). A 500 means authn could not finish
// the job (its own dependency failed): nothing is known to be wrong with the
// caller, and the same request may succeed later. A client can classify on the
// code alone and use the cause only to name the reason.
const (
	// Refusals of the caller (401/403).
	CauseMissingBearer         status.CauseType = "MissingBearer"
	CauseTokenNotAuthenticated status.CauseType = "TokenNotAuthenticated"
	CauseAudienceMismatch      status.CauseType = "AudienceMismatch"
	CauseNotAServiceAccount    status.CauseType = "NotAServiceAccount"
	CauseNoMapping             status.CauseType = "NoMapping"
	CauseAmbiguousMapping      status.CauseType = "AmbiguousMapping"

	// Failures of authn (500).
	CauseTokenReviewFailed   status.CauseType = "TokenReviewFailed"
	CauseMappingLookupFailed status.CauseType = "MappingLookupFailed"
	CauseIssuanceFailed      status.CauseType = "IssuanceFailed"
)

var errMissingBearer = errors.New("missing bearer token")

// causeError tags a login failure with its machine-readable cause and the
// status code that says whose failure it is.
type causeError struct {
	code  int
	cause status.CauseType
	err   error
}

func (e causeError) Error() string { return e.err.Error() }
func (e causeError) Unwrap() error { return e.err }

// rejected is a refusal of the caller (403).
func rejected(cause status.CauseType, err error) causeError {
	return causeError{code: http.StatusForbidden, cause: cause, err: err}
}

// authnFailure is a failure on authn's side (500): the caller may retry.
func authnFailure(cause status.CauseType, err error) causeError {
	return causeError{code: http.StatusInternalServerError, cause: cause, err: err}
}

// failureStatus renders a login failure as a Status with its code and cause.
// An error without a cause is authn's own failure.
func failureStatus(err error) status.Status {
	var ce causeError
	if !errors.As(err, &ce) {
		return status.New(http.StatusInternalServerError, err)
	}
	return status.New(ce.code, err).WithCause(ce.cause, ce.err.Error())
}
