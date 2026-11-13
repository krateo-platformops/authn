package delegate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/auditlog"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/krateo-platformops/plumbing/kubeutil"
	"github.com/rs/zerolog"
)

// idpLeeway absorbs clock drift between authn and the identity provider, as
// the ID token's validation does.
const idpLeeway = time.Minute

// idpAlgorithms are the signatures an identity provider's access token may
// carry: RSA, as the provider's JWKS publishes it (plumbing's key source
// reads RSA keys). Never none, never an HMAC, which would let a token sign
// itself with a public key.
var idpAlgorithms = []string{"RS256", "RS384", "RS512"}

// verifyIdPSubject verifies an identity provider's access token as the
// subject of an exchange (authn#155) and returns the person to issue for and
// the expiry the issued token may not pass.
//
//   - The token's issuer must be one the actor's mapping lists
//     (spec.delegation.subjectTokens): matched by the issuer of each listed
//     OIDCConfig, before the token is trusted, only to pick the keys. A
//     source that can't be resolved is skipped; only if no other source
//     issued the token is it authn's failure, since it may have.
//   - The OIDCConfig may not map identities through a RESTAction: an
//     exchange doesn't run one, so it would map the person differently from
//     their sign-in (Diego, 2026-11-13).
//   - It must verify against that provider's JWKS: an RSA signature, the
//     issuer exactly, an issue time and an expiry (RFC 9068 §2.2), and an
//     audience the source lists. A kid the provider's freshly fetched key set
//     doesn't hold, on a token issued before that fetch, is the token's fault
//     (jwtutil.NotPublished), never authn's.
//   - It must be an access token, not an ID or refresh token the same
//     provider signed: typ at+jwt in its header (RFC 9068 §2.1), or typ
//     Bearer in its claims (Keycloak).
//   - The person is mapped as /oidc/login maps an ID token: the username from
//     preferred_username (kubeutil.MakeDNS1123Compatible), the groups from
//     groups, the identity from iss and sub.
//   - config.VouchForExchange then runs a sign-in's identity checks, the
//     OIDCConfig's allowedGroups among them, and the claim-first rule.
//
// On a refusal it returns the record's reason; with
// auditlog.NoDelegationDenial it is authn's failure. Neither answers the
// provider's addresses, kids or verification detail: the server log has
// them. verified is the person once the token verified, so a refusal of a
// verified identity names them; nil before.
func (r *route) verifyIdPSubject(ctx context.Context, log zerolog.Logger, actor *sav1alpha1.ServiceAccount, token string) (
	subject jwtutil.UserInfo, exp time.Time, verified *jwtutil.UserInfo, why auditlog.DelegationDenial, err error) {
	invalid := func(public string, private error) (jwtutil.UserInfo, time.Time, *jwtutil.UserInfo, auditlog.DelegationDenial, error) {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.SubjectTokenInvalid, subjectInvalidPrivately(public, private)
	}
	failed := func(public string, private error) (jwtutil.UserInfo, time.Time, *jwtutil.UserInfo, auditlog.DelegationDenial, error) {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.NoDelegationDenial,
			status.FailedPrivately(CauseIssuanceFailed, errors.New(public), private)
	}

	sources := actor.Spec.Delegation.SubjectTokens
	if len(sources) == 0 {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.DelegationNotAllowed, status.Refused(CauseDelegationNotAllowed,
			errors.New("the actor's ServiceAccount mapping lists no identity provider whose tokens it may exchange (spec.delegation.subjectTokens)"))
	}
	unverified := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, unverified); err != nil {
		return invalid("the subject token isn't a JWT", err)
	}
	iss, _ := unverified["iss"].(string)

	// Pick the source whose provider issued the token.
	var source *sav1alpha1.SubjectTokenSource
	var keys resolvers.OIDCTokenKeys
	var unresolved []error
	for i := range sources {
		k, err := r.tokenKeys.TokenKeys(ctx, sources[i].OIDCConfig)
		if err != nil {
			unresolved = append(unresolved, fmt.Errorf("OIDCConfig %q: %w", sources[i].OIDCConfig, err))
			continue
		}
		if iss != "" && k.Issuer == iss {
			source, keys = &sources[i], k
			break
		}
	}
	switch {
	case source == nil && len(unresolved) > 0:
		// The token's provider may be one that couldn't be resolved: authn's
		// misconfiguration or the provider's outage, never a refusal.
		return failed("an identity provider the actor's mapping lists couldn't be resolved",
			fmt.Errorf("resolving the actor's subject-token sources: %w", errors.Join(unresolved...)))
	case source == nil:
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.DelegationNotAllowed, status.Refused(CauseDelegationNotAllowed,
			errors.New("the actor's ServiceAccount mapping lists no identity provider that issued this token"))
	case keys.MapsThroughRESTAction:
		return failed("this OIDCConfig maps identities through a RESTAction, which a token exchange doesn't run",
			fmt.Errorf("OIDCConfig %q sets restActionRef", source.OIDCConfig))
	}

	keySource := r.idpKeySource(keys.JWKSURI)
	claims := jwt.MapClaims{}
	parsed, err := jwt.NewParser(jwt.WithValidMethods(idpAlgorithms), jwt.WithIssuer(keys.Issuer),
		jwt.WithIssuedAt(), jwt.WithExpirationRequired(), jwt.WithLeeway(idpLeeway)).
		ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
			// The issue time is read before the signature is checked, only
			// to tell a key the provider no longer publishes (the token's
			// fault) from one its cached set predates (retry).
			iat, err := t.Claims.GetIssuedAt()
			if err != nil || iat == nil {
				return nil, errNoIssuedAt
			}
			if iat.After(time.Now().Add(idpLeeway)) {
				return nil, jwt.ErrTokenUsedBeforeIssued
			}
			kid, _ := t.Header["kid"].(string)
			key, err := keySource.PublicKey(kid)
			if err != nil {
				return nil, jwtutil.NotPublished(err, iat.Time)
			}
			return key, nil
		})
	switch {
	case errors.Is(err, jwtutil.ErrKeyNotPublished):
		return invalid("the subject token didn't verify against its identity provider", err)
	case errors.Is(err, jwtutil.ErrKeyUnavailable):
		// The provider's keys couldn't be read: not the token's fault.
		return failed("the identity provider's signing keys couldn't be read", err)
	case errors.Is(err, jwt.ErrTokenExpired):
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.SubjectTokenExpired, subjectInvalid(errors.New("the subject token has expired"))
	case err != nil:
		return invalid("the subject token didn't verify against its identity provider", err)
	}
	if !isAccessToken(parsed.Header, claims) {
		return invalid("the subject token isn't an access token", fmt.Errorf("header typ %v, claim typ %v", parsed.Header["typ"], claims["typ"]))
	}
	aud, err := claims.GetAudience()
	if err != nil || !slices.ContainsFunc(aud, func(a string) bool { return slices.Contains(source.Audiences, a) }) {
		return invalid("the subject token isn't for an audience the actor's subject-token source lists", fmt.Errorf("aud %v", claims["aud"]))
	}
	expAt, err := claims.GetExpirationTime()
	if err != nil || expAt == nil {
		return invalid("the subject token has no expiry", err)
	}
	if time.Until(expAt.Time) < time.Second {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.SubjectTokenExpired, subjectInvalid(errors.New("the subject token is about to expire"))
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return invalid("the subject token has no sub", nil)
	}
	preferred, ok := stringClaim(claims, "preferred_username")
	if !ok {
		return invalid("the subject token's preferred_username isn't a string", nil)
	}
	groups, ok := stringListClaim(claims, "groups")
	if !ok {
		return invalid("the subject token's groups aren't a list of strings", nil)
	}

	user := userinfo.NewDefaultUser(kubeutil.MakeDNS1123Compatible(preferred), "", groups, nil)
	user.Subject = userinfo.Subject{Issuer: keys.Issuer, ID: sub}
	person := jwtutil.UserInfo{Username: user.GetUserName(), Groups: user.GetGroups(), Principal: jwtutil.PrincipalHuman}

	lookup := r.opts.Lookup
	if lookup == nil {
		if lookup, err = kubeconfig.NewNameLookup(r.rc); err != nil {
			return failed("the name lookup couldn't be built", err)
		}
	}
	allowed := keys.AllowedGroups
	admit := kubeconfig.Admit(func(u userinfo.Info) error {
		if len(allowed) == 0 || slices.ContainsFunc(u.GetGroups(), func(g string) bool { return slices.Contains(allowed, g) }) {
			return nil
		}
		return kubeconfig.Refused(kubeconfig.RefusalGroupNotAllowed, status.Refused(CauseGroupNotAllowed,
			errors.New("the person is in none of the groups the OIDCConfig admits")))
	})
	if _, err := kubeconfig.VouchForExchange(ctx, lookup, r.opts.Naming, log, storage.StrategyOIDC, user, admit); err != nil {
		if why := kubeconfig.RefusalOf(err); why != "" {
			return jwtutil.UserInfo{}, time.Time{}, &person, auditlog.DelegationRefusal(why), err
		}
		return jwtutil.UserInfo{}, time.Time{}, &person, auditlog.NoDelegationDenial, err
	}
	return person, expAt.Time, &person, auditlog.NoDelegationDenial, nil
}

// errNoIssuedAt refuses an access token without iat, which RFC 9068 §2.2
// requires: without it a kid the provider doesn't publish can't be told from
// one its cached key set predates.
var errNoIssuedAt = errors.New("the token has no issue time (iat)")

// isAccessToken says whether a verified token is an access token: typ at+jwt
// in its header (RFC 9068 §2.1), or typ Bearer in its claims, as Keycloak
// marks its access tokens (its ID tokens carry typ ID, its refresh tokens
// typ Refresh).
func isAccessToken(header map[string]any, claims jwt.MapClaims) bool {
	typ, _ := header["typ"].(string)
	if strings.EqualFold(typ, "at+jwt") || strings.EqualFold(typ, "application/at+jwt") {
		return true
	}
	claimed, _ := claims["typ"].(string)
	return claimed == "Bearer"
}

// idpKeySource is the identity provider's key source for url, one per URL,
// so its keys are fetched once and refreshed as the source decides.
func (r *route) idpKeySource(url string) *jwtutil.JWKSKeySource {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.idpKeys[url]; ok {
		return s
	}
	s := jwtutil.NewJWKSKeySource(url)
	r.idpKeys[url] = s
	return s
}

// stringClaim is claims[key] as a string; absent is "", true; any other type
// is false.
func stringClaim(claims jwt.MapClaims, key string) (string, bool) {
	v, ok := claims[key]
	if !ok || v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

// stringListClaim is claims[key] as a list of strings; absent is nil, true;
// anything but a list of strings is false.
func stringListClaim(claims jwt.MapClaims, key string) ([]string, bool) {
	v, ok := claims[key]
	if !ok || v == nil {
		return nil, true
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
