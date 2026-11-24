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
	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"net/http"
	"strconv"
	"sync"
	"time"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
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
	// AssertionPath is the same exchange for an actor that authenticates with
	// a client assertion (RFC 7523): OAuth's token endpoint for it. Served on
	// the internal listener only, and only over TLS.
	AssertionPath = "/delegate/token"

	// GrantType, TokenTypeJWT and TokenTypeAccessToken are RFC 8693's
	// identifiers (§2.1, §3). A subject of TokenTypeJWT is an authn token; one
	// of TokenTypeAccessToken is an identity provider's access token, which
	// the actor's mapping must list a source for (authn#155).
	GrantType            = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

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
	CauseUnsupportedGrantType    status.CauseType = "UnsupportedGrantType"    // 400
	CauseUnsupportedSubjectToken status.CauseType = "UnsupportedSubjectToken" // 400
	CauseMissingSubjectToken     status.CauseType = "MissingSubjectToken"     // 400
	CauseSubjectTokenInvalid     status.CauseType = "SubjectTokenInvalid"     // 401
	// CauseInvalidTarget: the requested audience isn't one the actor's
	// mapping allows (RFC 8693's invalid_target, authn#155).
	CauseInvalidTarget status.CauseType = "InvalidTarget" // 400
	// CauseSubjectAudienceNotAllowed: an authn subject token verified but is
	// for another audience than the actor's (spec.delegation.subjectAudiences).
	CauseSubjectAudienceNotAllowed status.CauseType = "SubjectAudienceNotAllowed" // 403
	// CauseGroupNotAllowed: an identity provider's subject is in none of
	// its OIDCConfig's allowedGroups: /oidc/login's cause of the same name.
	CauseGroupNotAllowed status.CauseType = "GroupNotAllowed" // 403
	// CauseSubjectNotAPerson: an identity provider's subject token verified
	// but carries no user session (no sid): a service account's
	// client-credentials token names no person to act for (authn#165).
	CauseSubjectNotAPerson    status.CauseType = "SubjectNotAPerson"        // 403
	CauseDelegationNotAllowed status.CauseType = "DelegationNotAllowed"     // 403
	CauseDelegationTooDeep    status.CauseType = "DelegationTooDeep"        // 403
	CauseIssuanceFailed                        = status.CauseIssuanceFailed // 500
	// CauseSubjectKeyUnavailable: an identity provider's subject token
	// names a key authn can't read yet, because the provider's keys couldn't
	// be fetched or the set it has may predate the key (authn#155). Retry.
	CauseSubjectKeyUnavailable status.CauseType = "SubjectKeyUnavailable" // 503
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
	// Audit records each decision about an authenticated actor (AUDIT-4).
	// Nil records nothing.
	Audit *auditlog.Recorder
	// Lookup reads an identity provider subject's credential Secrets for the
	// claim-first rule (authn#155); nil builds one from the route's rest
	// config.
	Lookup kubeconfig.NameLookup
	// Naming is how session Secrets are named (authn#140): the claim-first
	// rule reads the Secrets a sign-in reads.
	Naming storage.Naming
	// Generator mints the credential issued with each delegated token
	// (authn#167). Without one, every exchange fails: a delegated token is
	// never issued without its credential.
	Generator kubeconfig.Generator
	// ClientAssertions serves AssertionPath instead of Path: the actor
	// authenticates with a client assertion (RFC 7523), never with its
	// ServiceAccount token. Only for the internal listener over TLS.
	ClientAssertions bool
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
	return &route{rc: rc, opts: opts, keys: keys, tokenKeys: resolvers.NewTokenKeysResolver(rc),
		idpKeys: map[string]*jwtutil.JWKSKeySource{}}
}

var _ routes.Route = (*route)(nil)

type route struct {
	rc   *rest.Config
	opts Options
	keys keySet

	// tokenKeys resolves the actor's subject-token sources (authn#155).
	tokenKeys *resolvers.TokenKeysResolver
	// idpKeys caches an identity provider's key source by its JWKS URL, so
	// its keys are fetched once and refreshed by the source (authn#155).
	mu      sync.Mutex
	idpKeys map[string]*jwtutil.JWKSKeySource

	// jtis are the client assertions already used.
	jtis seenJTIs
}

func (r *route) Name() string { return "delegate" }
func (r *route) Pattern() string {
	if r.opts.ClientAssertions {
		return AssertionPath
	}
	return Path
}
func (r *route) Method() string { return http.MethodPost }

func (r *route) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context())
		fail := func(err error, msg string) {
			status.LogFailure(*log, err).Msg(msg)
			if secs, ok := status.RetryAfter(err); ok {
				wri.Header().Set("Retry-After", strconv.Itoa(secs))
			}
			encode.Failure(wri, status.FromError(err))
		}

		token, ok := serviceaccount.BearerToken(req)
		if !ok && !r.opts.ClientAssertions {
			wri.Header().Set("WWW-Authenticate", `Bearer realm="krateo"`)
			err := errors.New("the actor's ServiceAccount token must be sent as Authorization: Bearer")
			encode.Failure(wri, status.New(http.StatusUnauthorized, err).
				WithCause(serviceaccount.CauseMissingBearer, err.Error()))
			return
		}

		x, err := readExchange(req)
		if err != nil {
			fail(err, "delegation request refused")
			return
		}

		var actor *sav1alpha1.ServiceAccount
		if r.opts.ClientAssertions {
			// One that isn't authenticated has no record, as a ServiceAccount
			// token that doesn't verify has none.
			actor, err = r.authenticateAssertion(req)
		} else {
			var verified serviceaccount.Verified
			actor, verified, err = serviceaccount.Authenticate(req.Context(), r.rc, r.opts.Audience, token)
			if err != nil {
				// An actor the TokenReview verified is recorded however it was
				// refused or failed at its mapping (authn#132).
				serviceaccount.RecordUnmapped(r.opts.Audit, req, auditlog.ActionDelegate, verified)
			}
		}
		if err != nil {
			fail(err, "delegation actor not authenticated")
			return
		}
		actorPrincipal := serviceaccount.Principal(actor)
		maxDepth, err := delegationDepth(actor)
		if err != nil {
			r.opts.Audit.Delegation(req, actor, actorPrincipal, nil, nil, audit.OutcomeDenied, auditlog.DelegationNotAllowed, "")
			fail(err, "delegation refused")
			return
		}

		// The audience is checked against the actor's mapping, so after it.
		audience, why, err := requestedAudience(actor, x.audiences)
		if err != nil {
			r.opts.Audit.Delegation(req, actor, actorPrincipal, nil, nil, audit.OutcomeDenied, why, audience)
			fail(err, "delegation audience refused")
			return
		}

		var subject jwtutil.UserInfo
		var exp time.Time
		// The person's identity, recorded on the delegated credential: an
		// identity provider's token's strategy and claim, vouched for against
		// the person's session Secret, or for an authn token, the ones that
		// Secret records.
		strategy, claim := storage.StrategyOIDC, ""
		if x.subjectType == TokenTypeAccessToken {
			var verified *jwtutil.UserInfo
			subject, exp, claim, verified, why, err = r.verifyIdPSubject(req.Context(), *log, actor, x.subjectToken)
			if err != nil {
				// A refusal of a subject the provider verified names them.
				if why == auditlog.NoDelegationDenial {
					r.opts.Audit.Delegation(req, actor, actorPrincipal, verified, nil, audit.OutcomeFailure, why, "")
					fail(err, "delegation failed verifying the subject token")
					return
				}
				r.opts.Audit.Delegation(req, actor, actorPrincipal, verified, nil, audit.OutcomeDenied, why, "")
				fail(err, "delegation subject token refused")
				return
			}
		} else {
			var verified *jwtutil.UserInfo
			subject, exp, verified, why, err = r.verifySubject(actor, x.subjectToken)
			if err != nil {
				// The actor is verified: refusing its subject token is a decision
				// about it, and the most security-relevant one. A token that
				// verified and is for someone else names its person.
				r.opts.Audit.Delegation(req, actor, actorPrincipal, verified, nil, audit.OutcomeDenied, why, "")
				fail(err, "delegation subject token refused")
				return
			}
		}

		act := &jwtutil.Actor{Sub: actor.Name, Act: subject.Act, Principal: actorPrincipal}
		depth := chainDepth(act)
		if depth > maxDepth {
			r.opts.Audit.Delegation(req, actor, actorPrincipal, &subject, act, audit.OutcomeDenied, auditlog.DelegationTooDeep, "")
			fail(status.Refused(CauseDelegationTooDeep,
				fmt.Errorf("the actor chain would be %d deep; the actor's ServiceAccount mapping allows %d", depth, maxDepth)),
				"delegation refused")
			return
		}

		if x.subjectType != TokenTypeAccessToken {
			lookup, err := r.nameLookup()
			if err == nil {
				strategy, claim, err = kubeconfig.SessionIdentity(req.Context(), lookup, r.opts.Naming, *log, subject.Username)
			}
			if err != nil {
				if why := kubeconfig.RefusalOf(err); why != "" {
					r.opts.Audit.Delegation(req, actor, actorPrincipal, &subject, act, audit.OutcomeDenied, auditlog.DelegationRefusal(why), "")
					fail(err, "delegation refused")
					return
				}
				r.opts.Audit.Delegation(req, actor, actorPrincipal, &subject, act, audit.OutcomeFailure, auditlog.NoDelegationDenial, "")
				fail(status.Failed(CauseIssuanceFailed, err), "delegation failed reading the person's session credential")
				return
			}
		}

		// authn#167: the groups are bound once. They are the token's groups
		// claim and its credential's certificate O alike, so a reader that
		// checks one against the other (endpoints.CheckDelegatedCredential)
		// never finds them apart.
		groups := withoutReserved(subject.Groups)
		ttl := min(r.opts.TTL, time.Until(exp))
		credential, err := r.issueCredential(req, *log, strategy, subject, groups, actor.Name, claim, ttl)
		if err != nil {
			if why := kubeconfig.RefusalOf(err); why != "" {
				r.opts.Audit.Delegation(req, actor, actorPrincipal, &subject, act, audit.OutcomeDenied, auditlog.DelegationRefusal(why), "")
				fail(err, "delegation refused")
				return
			}
			r.opts.Audit.Delegation(req, actor, actorPrincipal, &subject, act, audit.OutcomeFailure, auditlog.NoDelegationDenial, "")
			fail(status.IssueFailure("delegated credential", err), "delegation failed issuing its credential")
			return
		}
		// The token never outlives its credential: the signer may grant less
		// than was asked.
		ttl = min(ttl, time.Until(credential.NotAfter))

		issued, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
			Username:   subject.Username,
			Groups:     groups,
			Duration:   ttl,
			KeyID:      r.opts.KeyID,
			PrivateKey: r.opts.PrivateKey,
			Act:        act,
			Principal:  subject.Principal,
			Audience:   audiences(audience),
		})
		if err != nil {
			r.opts.Audit.Delegation(req, actor, actorPrincipal, &subject, act, audit.OutcomeFailure, auditlog.NoDelegationDenial, "")
			fail(status.Failed(CauseIssuanceFailed, fmt.Errorf("signing the delegated token: %w", err)), "delegation failed")
			return
		}
		r.opts.Audit.Delegation(req, actor, actorPrincipal, &subject, act, audit.OutcomeSuccess, auditlog.NoDelegationDenial, audience)

		// Neither the actor nor the subject is logged: the delegation's audit
		// record names both (session.id joins them).
		log.Info().Str("principal", string(actorPrincipal)).Int("depth", depth).
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

// issueCredential mints the credential issued with a delegated token for
// subject through actor (authn#167): a certificate for exactly the token's
// username and groups, valid for ttl. The person's session Secret is not
// touched. The write is recorded (AUDIT-4) whatever its outcome.
func (r *route) issueCredential(req *http.Request, log zerolog.Logger, strategy storage.Strategy, subject jwtutil.UserInfo, groups []string, actor, claim string, ttl time.Duration) (kubeconfig.Issued, error) {
	if r.opts.Generator == nil {
		return kubeconfig.Issued{}, status.Failed(CauseIssuanceFailed, errors.New("no credential generator is configured for delegated tokens"))
	}
	person := userinfo.NewDefaultUser(subject.Username, "", groups, nil)
	issued, err := r.opts.Generator.GenerateDelegated(strategy, person, actor, claim, ttl, kubeconfig.Logger(log))
	r.opts.Audit.Issuance(req, auditlog.ActionDelegateCredential, person, subject.Principal, issued, err)
	return issued, err
}

// nameLookup is the lookup the claim-first rule and an authn token's session
// identity read Secrets through.
func (r *route) nameLookup() (kubeconfig.NameLookup, error) {
	if r.opts.Lookup != nil {
		return r.opts.Lookup, nil
	}
	return kubeconfig.NewNameLookup(r.rc)
}

// response is RFC 8693's token exchange response (§2.2.1).
type response struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// exchangeRequest is RFC 8693's form, as sent.
type exchangeRequest struct {
	subjectToken string
	subjectType  string
	// audiences are the audience parameters as sent; requestedAudience
	// checks them against the actor's mapping.
	audiences []string
}

// readExchange reads RFC 8693's form parameters: the grant type, the subject
// token and its type, and the audience. A malformed request is refused here,
// before the actor is authenticated, so it writes no record, as today.
func readExchange(req *http.Request) (exchangeRequest, error) {
	if err := req.ParseForm(); err != nil {
		return exchangeRequest{}, status.BadRequest(status.CauseInvalidRequestBody, fmt.Errorf("the body is not a form: %w", err))
	}
	// The caller's values aren't repeated: the error is logged.
	if g := req.PostForm.Get("grant_type"); g != GrantType {
		return exchangeRequest{}, status.BadRequest(CauseUnsupportedGrantType, fmt.Errorf("grant_type must be %q", GrantType))
	}
	t := req.PostForm.Get("subject_token_type")
	if t != TokenTypeJWT && t != TokenTypeAccessToken {
		return exchangeRequest{}, status.BadRequest(CauseUnsupportedSubjectToken, fmt.Errorf("subject_token_type must be %q or %q", TokenTypeJWT, TokenTypeAccessToken))
	}
	subject := req.PostForm.Get("subject_token")
	if subject == "" {
		return exchangeRequest{}, status.BadRequest(CauseMissingSubjectToken, errors.New("subject_token is required"))
	}
	return exchangeRequest{subjectToken: subject, subjectType: t, audiences: req.PostForm["audience"]}, nil
}

// requestedAudience is the audience the issued token is for (RFC 8693
// §2.1's audience, authn#155), or "" when none was requested. At most one
// may be sent, in audit's token_audience format, and the actor's mapping
// must list it (spec.delegation.audiences); a listed entry audit wouldn't
// record never matches. The refusals are a decision about the verified
// actor, so each returns its record's reason and the audience it may name.
func requestedAudience(actor *sav1alpha1.ServiceAccount, sent []string) (string, auditlog.DelegationDenial, error) {
	switch {
	case len(sent) == 0 && actor.Spec.Delegation.AudienceRequired:
		return "", auditlog.InvalidRequest, status.BadRequest(CauseInvalidTarget,
			errors.New("the actor's ServiceAccount mapping requires an audience (spec.delegation.audienceRequired)"))
	case len(sent) == 0:
		return "", auditlog.NoDelegationDenial, nil
	case len(sent) > 1:
		return "", auditlog.InvalidRequest, status.BadRequest(status.CauseInvalidRequestBody, errors.New("at most one audience may be requested"))
	case !audit.ValidTokenAudience(sent[0]):
		return "", auditlog.InvalidRequest, status.BadRequest(status.CauseInvalidRequestBody,
			errors.New("the audience must be a DNS-1123 subdomain or an https URI with a DNS-1123 host, an optional port and a path of unreserved characters"))
	}
	want := sent[0]
	for _, a := range actor.Spec.Delegation.Audiences {
		if a == want && audit.ValidTokenAudience(a) {
			return want, auditlog.NoDelegationDenial, nil
		}
	}
	return want, auditlog.AudienceNotAllowed, status.BadRequest(CauseInvalidTarget,
		errors.New("the actor's ServiceAccount mapping doesn't allow this audience (spec.delegation.audiences)"))
}

// audiences is the issued token's aud: the requested audience, or none.
func audiences(a string) []string {
	if a == "" {
		return nil
	}
	return []string{a}
}

// delegationDepth returns how deep a chain the actor's mapping allows, or
// refuses an actor that hasn't opted in.
func delegationDepth(actor *sav1alpha1.ServiceAccount) (int, error) {
	d := actor.Spec.Delegation
	if d == nil || !d.Allowed {
		return 0, status.Refused(CauseDelegationNotAllowed,
			errors.New("the actor's ServiceAccount mapping doesn't set spec.delegation.allowed"))
	}
	maxDepth := DefaultMaxDepth
	if d.MaxDepth != nil {
		maxDepth = int(*d.MaxDepth)
	}
	return min(maxDepth, jwtutil.MaxActorDepth), nil
}

// verifySubject checks that authn signed the subject token, with its current
// key or a previous one, that it hasn't expired, and that it isn't meant for
// another audience than the actor's. It returns the token's identity and
// expiry, or the refusal with its record's reason: expired for a token that
// verified but has lapsed or is about to, invalid for one that didn't verify (a
// bad signature, a kid authn has no key for, a retired one among them,
// malformed, or no expiry, which authn never issues). The answer is
// SubjectTokenInvalid either way; only the record tells them apart.
//
// A token for another audience is SubjectAudienceNotAllowed. Exchanging it
// would turn a token one service accepts into one another does, so only a
// service it is for may. It verified: its identity is returned for the record.
func (r *route) verifySubject(actor *sav1alpha1.ServiceAccount, token string) (jwtutil.UserInfo, time.Time, *jwtutil.UserInfo, auditlog.DelegationDenial, error) {
	refuse := func(why auditlog.DelegationDenial, err error) (jwtutil.UserInfo, time.Time, *jwtutil.UserInfo, auditlog.DelegationDenial, error) {
		return jwtutil.UserInfo{}, time.Time{}, nil, why, subjectInvalid(err)
	}
	claims, err := jwtutil.ValidateClaimsWithKeySource(r.keys, token,
		jwtutil.WithAudience(actor.Spec.Delegation.SubjectAudiences...))
	switch {
	case errors.Is(err, jwtutil.ErrAudienceMismatch):
		// audit has no reason of its own for it yet (snowplow adds one).
		return jwtutil.UserInfo{}, time.Time{}, &claims.UserInfo, auditlog.SubjectTokenInvalid,
			status.Refused(CauseSubjectAudienceNotAllowed, errors.New("the subject token is for another audience than this service's (spec.delegation.subjectAudiences)"))
	case errors.Is(err, jwtutil.ErrTokenExpired):
		return refuse(auditlog.SubjectTokenExpired, fmt.Errorf("the subject token has expired: %w", err))
	case err != nil:
		return refuse(auditlog.SubjectTokenInvalid, fmt.Errorf("the subject token isn't a valid authn token: %w", err))
	}
	if claims.ExpiresAt == nil {
		return refuse(auditlog.SubjectTokenInvalid, errors.New("the subject token has no expiry"))
	}
	exp := claims.ExpiresAt.Time
	if time.Until(exp) < time.Second {
		return refuse(auditlog.SubjectTokenExpired, errors.New("the subject token is about to expire"))
	}
	return claims.UserInfo, exp, nil, auditlog.NoDelegationDenial, nil
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

// subjectKeyUnavailable answers public with 503 SubjectKeyUnavailable and
// Retry-After retryAfter, the key source's detail kept private for the
// server log.
func subjectKeyUnavailable(public string, private error, retryAfter time.Duration) status.CauseError {
	return status.CauseError{Code: http.StatusServiceUnavailable, Cause: CauseSubjectKeyUnavailable,
		Err: errors.New(public), Private: private, RetryAfter: retryAfter}
}

// subjectInvalidPrivately is subjectInvalid answering public, with the
// verification's detail, which may name the provider's key URL or a kid,
// kept private for the server log.
func subjectInvalidPrivately(public string, private error) status.CauseError {
	return status.CauseError{Code: http.StatusUnauthorized, Cause: CauseSubjectTokenInvalid, Err: errors.New(public), Private: private}
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
