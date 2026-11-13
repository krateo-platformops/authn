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
	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"net/http"
	"strings"
	"time"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/shortid"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/rs/zerolog"
	authnv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	// Audit records each verified identity\'s credential write (AUDIT-4). Nil records nothing.
	Audit         *auditlog.Recorder
	JwtDuration   time.Duration
	JwtPrivateKey *rsa.PrivateKey
	JwtKeyID      string
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
		audit:         opts.Audit,
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
	audit         *auditlog.Recorder
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

		token, ok := BearerToken(req)
		if !ok {
			wri.Header().Set("WWW-Authenticate", `Bearer realm="krateo"`)
			encode.Failure(wri, status.New(http.StatusUnauthorized, errMissingBearer).
				WithCause(CauseMissingBearer, errMissingBearer.Error()))
			return
		}

		user, principal, owner, verified, err := r.validate(req.Context(), token)
		if err != nil {
			// A caller the TokenReview verified is recorded however it was
			// refused or failed (authn#132); one refused before that is not.
			RecordUnmapped(r.audit, req, auditlog.LoginAction(storage.StrategyServiceAccount), verified)
			status.LogFailure(*log, err).Msg("serviceaccount auth failed")
			encode.Failure(wri, status.FromError(err))
			return
		}
		log.Debug().Str("principal", string(principal)).Int("groups", len(user.GetGroups())).
			Msg("serviceaccount auth succeeded")

		// Generate mints the client certificate and persists the identity's
		// <username>-clientconfig Secret, which in-cluster consumers (snowplow,
		// plumbing endpoints, bff) read. The kubeconfig it returns is NOT put in
		// the response: it carries client-key-data, a private key, and no
		// service caller reads it; they all use accessToken alone. Keeping it
		// out of the body means printing or logging a successful response can't
		// leak the key (#36).
		// The Secret is owned by the mapping, so whoever retires the mapping
		// (core-provider, on Undeploy) retires the credential with it, through
		// the garbage collector, without needing delete rights on Secrets.
		// The mapping's declared kind is the Secret's principal label (with exact
		// naming on, authn#140, authn#144): never human, whatever its groups.
		issued, err := r.gen.Generate(storage.StrategyServiceAccount, user, kubeconfig.OwnedBy(owner),
			kubeconfig.AsPrincipal(string(principal)), kubeconfig.Logger(*log))
		r.audit.Issuance(req, auditlog.LoginAction(storage.StrategyServiceAccount), user, principal, issued, err)
		if err != nil {
			err = status.IssueFailure("clientconfig", err)
			status.LogFailure(*log, err).Msg("kubeconfig creation failure")
			encode.Failure(wri, status.FromError(err))
			return
		}

		err = encode.Success(wri, nil, &encode.Extras{
			UserInfo:      user,
			Strategy:      &encode.Strategy{Kind: string(storage.StrategyServiceAccount)},
			JwtDuration:   r.jwtDuration,
			JwtPrivateKey: r.jwtPrivateKey,
			JwtKeyID:      r.jwtKeyID,
			CertNotAfter:  issued.NotAfter,
			Principal:     principal,
		})
		if err != nil {
			// Success has already answered with IssuanceFailed.
			log.Err(err).Msg("access token creation failure")
		}
	}
}

// validate authenticates the SA token (Authenticate) and builds the issued
// identity (username = mapping name, groups = mapping spec.groups). Verified
// is what Authenticate established, whatever the outcome.
func (r *loginRoute) validate(ctx context.Context, token string) (userinfo.Info, jwtutil.Principal, metav1.OwnerReference, Verified, error) {
	mapping, v, err := Authenticate(ctx, r.rc, r.audience, token)
	if err != nil {
		return nil, "", metav1.OwnerReference{}, v, err
	}

	exts := userinfo.Extensions{}
	exts.Add("name", mapping.Spec.DisplayName)

	uid, _ := shortid.Generate()
	nfo := userinfo.NewDefaultUser(mapping.Name, uid, mapping.Spec.Groups, exts)
	// The ServiceAccount, not the mapping: a mapping re-created for the same
	// ServiceAccount is the same identity, under a new UID.
	if ref := mapping.Spec.ServiceAccountRef; ref != nil {
		nfo.Subject = userinfo.Subject{Issuer: ref.Namespace, ID: ref.Name}
	}
	return nfo, Principal(mapping), mapping.OwnerReference(), v, nil
}

// Principal is the kind of identity a ServiceAccount mapping declares in
// spec.principal: agent, controller, or service when it declares none.
// It is the rule the Secret's principal label follows (storage.PrincipalFor),
// so the token and the Secret can't disagree.
func Principal(mapping *sav1alpha1.ServiceAccount) jwtutil.Principal {
	p, _ := storage.PrincipalFor(storage.StrategyServiceAccount, mapping.Spec.Principal)
	return jwtutil.Principal(p)
}

// Verified is what Authenticate established about its caller, so a route can
// record a refusal or failure that came after verification (authn#132).
//
// User is the TokenReview's username once the token verified for authn's
// audience, and "" before that: a token addressed elsewhere isn't verified for
// authn. Denial says why a verified caller was refused at the mapping lookup,
// and LookupStatus is the apiserver's answer when that lookup failed with one
// (0 when nothing answered).
type Verified struct {
	User         string
	Denial       auditlog.MappingDenial
	LookupStatus int
}

// Authenticate verifies a projected ServiceAccount token through the
// Kubernetes TokenReview API, bound to audience, and returns the one
// ServiceAccount mapping (the allowlist) that names its ServiceAccount. Its
// errors carry this package's causes: a refusal of the caller, or authn's own
// failure to check. Verified is set whatever the outcome.
func Authenticate(ctx context.Context, rc *rest.Config, audience, token string) (*sav1alpha1.ServiceAccount, Verified, error) {
	var v Verified
	clientset, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, v, status.Failed(CauseTokenReviewFailed, fmt.Errorf("token review: building the client: %w", err))
	}

	tr := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{audience},
		},
	}
	tr, err = clientset.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, v, status.Failed(CauseTokenReviewFailed, fmt.Errorf("token review: %w", err))
	}
	if !tr.Status.Authenticated {
		// status.error is the apiserver's verdict on the caller's token
		// (invalid signature, expired, deleted ServiceAccount): a refusal of
		// the caller, not a failure of authn. Its text isn't authn's and can
		// name the ServiceAccount, so it is answered to the caller and never
		// logged (Answered).
		ce := status.Refused(CauseTokenNotAuthenticated, errors.New("token not authenticated"))
		ce.Answered = tr.Status.Error
		return nil, v, ce
	}
	if !containsAudience(tr.Status.Audiences, audience) {
		return nil, v, status.Refused(CauseAudienceMismatch, fmt.Errorf("token audience mismatch (require %q)", audience))
	}
	// Verified for authn: every refusal or failure from here on is recorded.
	v.User = tr.Status.User.Username

	saNamespace, saName, err := parseServiceAccountUsername(tr.Status.User.Username)
	if err != nil {
		v.Denial = auditlog.NotAServiceAccount
		return nil, v, status.Refused(CauseNotAServiceAccount, err)
	}

	mapping, err := resolvers.ServiceAccountForSA(rc, saNamespace, saName)
	switch {
	case errors.Is(err, resolvers.ErrNoMapping):
		v.Denial = auditlog.MappingMissing
		return nil, v, status.Refused(CauseNoMapping, err)
	case errors.Is(err, resolvers.ErrAmbiguousMapping):
		v.Denial = auditlog.MappingAmbiguous
		return nil, v, status.Refused(CauseAmbiguousMapping, err)
	case err != nil:
		// The apiserver's answer to the lookup when it gave one; never authn's
		// own 500, which is no authority's answer.
		var answered apierrors.APIStatus
		if errors.As(err, &answered) {
			v.LookupStatus = int(answered.Status().Code)
		}
		return nil, v, status.Failed(CauseMappingLookupFailed, err)
	}
	return mapping, v, nil
}

// RecordUnmapped records a caller Authenticate verified but refused or failed
// at the mapping lookup, under action: denied with its reason, or a failure
// with the apiserver's answer. A caller refused before verification has no
// User and gets no record.
func RecordUnmapped(rec *auditlog.Recorder, req *http.Request, action string, v Verified) {
	if v.User == "" {
		return
	}
	outcome := audit.OutcomeFailure
	if v.Denial != auditlog.NoMappingDenial {
		outcome = audit.OutcomeDenied
	}
	rec.Unmapped(req, action, v.User, outcome, v.Denial, v.LookupStatus)
}

// BearerToken returns the request's Authorization: Bearer token.
func BearerToken(req *http.Request) (string, bool) {
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
		return "", "", errors.New("not a service account token (its username isn't system:serviceaccount:<namespace>:<name>)")
	}
	parts := strings.SplitN(strings.TrimPrefix(u, prefix), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("malformed service account username")
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
	CauseIssuanceFailed                       = status.CauseIssuanceFailed
)

var errMissingBearer = errors.New("missing bearer token")
