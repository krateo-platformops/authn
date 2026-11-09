// Package delegate implements POST /delegate: a service exchanges a signed-in
// person's authn JWT for a short-lived one that names the person as subject and
// the service as actor (RFC 8693 token exchange, "act" claim), so an audit
// record can say who acted and for whom. See docs/design/agent-delegation.md.
package delegate

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/routes/auth/serviceaccount"
	"github.com/krateo-platformops/authn/internal/routes/jwks"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/rs/zerolog"
	"k8s.io/client-go/rest"
)

const (
	Path = "/delegate"

	// GrantType and TokenTypeJWT are RFC 8693's identifiers (§2.1, §3).
	GrantType    = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// DefaultTTL is the longest a delegated token lives. It never outlives
	// the subject token.
	DefaultTTL = 15 * time.Minute
	// DefaultMaxDepth caps the actor chain when the mapping doesn't set
	// spec.delegation.maxDepth.
	DefaultMaxDepth = 3
)

// Causes of a failed delegation besides the actor's, which are
// /serviceaccount/login's (serviceaccount.Cause*): the values of
// details.causes[0].reason (docs/api.md). They are added, never renamed.
const (
	// Refusals of the caller.
	CauseUnsupportedGrantType    status.CauseType = "UnsupportedGrantType"     // 400
	CauseUnsupportedSubjectToken status.CauseType = "UnsupportedSubjectToken"  // 400
	CauseMissingSubjectToken     status.CauseType = "MissingSubjectToken"      // 400
	CauseSubjectTokenInvalid     status.CauseType = "SubjectTokenInvalid"      // 401
	CauseDelegationNotAllowed    status.CauseType = "DelegationNotAllowed"     // 403
	CauseDelegationTooDeep       status.CauseType = "DelegationTooDeep"        // 403
	CauseIssuanceFailed                           = status.CauseIssuanceFailed // 500
)

type Options struct {
	// Audience the actor's projected ServiceAccount token must carry; defaults
	// to serviceaccount.DefaultAudience.
	Audience   string
	PrivateKey *rsa.PrivateKey
	KeyID      string
	// PreviousKeys verify subject tokens signed before a key rotation.
	PreviousKeys []jwks.Key
	// TTL is the longest a delegated token lives; defaults to DefaultTTL.
	TTL time.Duration
}

func Route(rc *rest.Config, opts Options) routes.Route {
	if opts.Audience == "" {
		opts.Audience = serviceaccount.DefaultAudience
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	keys := keySet{opts.KeyID: &opts.PrivateKey.PublicKey}
	for _, k := range opts.PreviousKeys {
		keys[k.KID] = k.Pub
	}
	return &route{rc: rc, opts: opts, keys: keys}
}

var _ routes.Route = (*route)(nil)

type route struct {
	rc   *rest.Config
	opts Options
	keys keySet
}

func (r *route) Name() string    { return "delegate" }
func (r *route) Pattern() string { return Path }
func (r *route) Method() string  { return http.MethodPost }

func (r *route) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context())
		fail := func(err error, msg string) {
			status.LogFailure(*log, err).Msg(msg)
			encode.Failure(wri, status.FromError(err))
		}

		token, ok := serviceaccount.BearerToken(req)
		if !ok {
			wri.Header().Set("WWW-Authenticate", `Bearer realm="krateo"`)
			err := errors.New("the actor's ServiceAccount token must be sent as Authorization: Bearer")
			encode.Failure(wri, status.New(http.StatusUnauthorized, err).
				WithCause(serviceaccount.CauseMissingBearer, err.Error()))
			return
		}

		subjectToken, err := exchangeRequest(req)
		if err != nil {
			fail(err, "delegation request refused")
			return
		}

		actor, err := serviceaccount.Authenticate(req.Context(), r.rc, r.opts.Audience, token)
		if err != nil {
			fail(err, "delegation actor not authenticated")
			return
		}
		maxDepth, err := delegationDepth(actor)
		if err != nil {
			fail(err, "delegation refused")
			return
		}

		subject, exp, err := r.verifySubject(subjectToken)
		if err != nil {
			fail(err, "delegation subject token refused")
			return
		}

		act := &jwtutil.Actor{Sub: actor.Name, Act: subject.Act, Principal: serviceaccount.Principal(actor)}
		depth := chainDepth(act)
		if depth > maxDepth {
			fail(status.Refused(CauseDelegationTooDeep,
				fmt.Errorf("the actor chain would be %d deep; %s allows %d", depth, actor.Name, maxDepth)),
				"delegation refused")
			return
		}

		ttl := min(r.opts.TTL, time.Until(exp))
		issued, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
			Username:   subject.Username,
			Groups:     withoutReserved(subject.Groups),
			Duration:   ttl,
			KeyID:      r.opts.KeyID,
			PrivateKey: r.opts.PrivateKey,
			Act:        act,
			Principal:  subject.Principal,
		})
		if err != nil {
			fail(status.Failed(CauseIssuanceFailed, fmt.Errorf("signing the delegated token: %w", err)), "delegation failed")
			return
		}

		log.Info().Str("actor", actor.Name).Str("subject", subject.Username).Int("depth", depth).
			Msg("delegated token issued")
		wri.Header().Set("Content-Type", "application/json")
		wri.Header().Set("Cache-Control", "no-store")
		wri.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(wri).Encode(response{
			AccessToken:     issued,
			IssuedTokenType: TokenTypeJWT,
			TokenType:       "Bearer",
			ExpiresIn:       int64(ttl / time.Second),
		})
	}
}

// response is RFC 8693's token exchange response (§2.2.1).
type response struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// exchangeRequest reads RFC 8693's form parameters and returns the subject
// token.
func exchangeRequest(req *http.Request) (string, error) {
	if err := req.ParseForm(); err != nil {
		return "", status.BadRequest(status.CauseInvalidRequestBody, fmt.Errorf("the body is not a form: %w", err))
	}
	if g := req.PostForm.Get("grant_type"); g != GrantType {
		return "", status.BadRequest(CauseUnsupportedGrantType, fmt.Errorf("grant_type must be %q, got %q", GrantType, g))
	}
	if t := req.PostForm.Get("subject_token_type"); t != TokenTypeJWT {
		return "", status.BadRequest(CauseUnsupportedSubjectToken, fmt.Errorf("subject_token_type must be %q, got %q", TokenTypeJWT, t))
	}
	subject := req.PostForm.Get("subject_token")
	if subject == "" {
		return "", status.BadRequest(CauseMissingSubjectToken, errors.New("subject_token is required"))
	}
	return subject, nil
}

// delegationDepth returns how deep a chain the actor's mapping allows, or
// refuses an actor that hasn't opted in.
func delegationDepth(actor *sav1alpha1.ServiceAccount) (int, error) {
	d := actor.Spec.Delegation
	if d == nil || !d.Allowed {
		return 0, status.Refused(CauseDelegationNotAllowed,
			fmt.Errorf("the ServiceAccount mapping %s doesn't set spec.delegation.allowed", actor.Name))
	}
	maxDepth := DefaultMaxDepth
	if d.MaxDepth != nil {
		maxDepth = int(*d.MaxDepth)
	}
	return min(maxDepth, jwtutil.MaxActorDepth), nil
}

// verifySubject checks that authn signed the subject token, with its current
// key or a previous one, and that it hasn't expired. It returns the token's
// identity and expiry.
func (r *route) verifySubject(token string) (jwtutil.UserInfo, time.Time, error) {
	claims, err := jwtutil.ValidateClaimsWithKeySource(r.keys, token)
	if err != nil {
		return jwtutil.UserInfo{}, time.Time{}, subjectInvalid(
			fmt.Errorf("the subject token isn't a valid authn token: %w", err))
	}
	if claims.ExpiresAt == nil {
		return jwtutil.UserInfo{}, time.Time{}, subjectInvalid(errors.New("the subject token has no expiry"))
	}
	exp := claims.ExpiresAt.Time
	if time.Until(exp) < time.Second {
		return jwtutil.UserInfo{}, time.Time{}, subjectInvalid(errors.New("the subject token is about to expire"))
	}
	return claims.UserInfo, exp, nil
}

// withoutReserved drops reserved groups: a krateo:loa: step-up group proves a
// fresh, stronger sign-in by the person, which an actor didn't make.
func withoutReserved(groups []string) []string {
	kept := []string{}
	for _, g := range groups {
		if !userinfo.IsReserved(g) {
			kept = append(kept, g)
		}
	}
	return kept
}

// subjectInvalid refuses a subject token authn didn't sign, or that has
// expired (401): the caller must get a fresh one from the person's session.
func subjectInvalid(err error) status.CauseError {
	return status.CauseError{Code: http.StatusUnauthorized, Cause: CauseSubjectTokenInvalid, Err: err}
}

// chainDepth counts the actors in a chain.
func chainDepth(a *jwtutil.Actor) int {
	n := 0
	for ; a != nil; a = a.Act {
		n++
	}
	return n
}

// keySet resolves authn's own verification keys by kid.
type keySet map[string]*rsa.PublicKey

func (k keySet) PublicKey(kid string) (*rsa.PublicKey, error) {
	if pub, ok := k[kid]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("no authn key with kid %q", kid)
}
