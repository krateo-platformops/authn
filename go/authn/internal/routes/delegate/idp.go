package delegate

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
//     OIDCConfig, before the token is trusted, only to pick the keys.
//   - It must verify against that provider's JWKS: an RSA signature, the
//     issuer exactly, an expiry not passed, and an audience the source lists.
//   - The person is mapped as /oidc/login maps an ID token: the username from
//     preferred_username (kubeutil.MakeDNS1123Compatible), the groups from
//     groups, the identity from iss and sub.
//   - config.VouchForExchange then runs a sign-in's identity checks, the
//     OIDCConfig's allowedGroups among them, and the claim-first rule.
//
// On a refusal it returns the record's reason; with
// auditlog.NoDelegationDenial it is authn's failure. verified is the person
// once the token verified, so a refusal of a verified identity names them;
// nil before.
func (r *route) verifyIdPSubject(ctx context.Context, log zerolog.Logger, actor *sav1alpha1.ServiceAccount, token string) (
	subject jwtutil.UserInfo, exp time.Time, verified *jwtutil.UserInfo, why auditlog.DelegationDenial, err error) {
	invalid := func(err error) (jwtutil.UserInfo, time.Time, *jwtutil.UserInfo, auditlog.DelegationDenial, error) {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.SubjectTokenInvalid, subjectInvalid(err)
	}
	failed := func(err error) (jwtutil.UserInfo, time.Time, *jwtutil.UserInfo, auditlog.DelegationDenial, error) {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.NoDelegationDenial, status.Failed(CauseIssuanceFailed, err)
	}

	sources := actor.Spec.Delegation.SubjectTokens
	if len(sources) == 0 {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.DelegationNotAllowed, status.Refused(CauseDelegationNotAllowed,
			errors.New("the actor's ServiceAccount mapping lists no identity provider whose tokens it may exchange (spec.delegation.subjectTokens)"))
	}
	unverified := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, unverified); err != nil {
		return invalid(fmt.Errorf("the subject token isn't a JWT: %w", err))
	}
	iss, _ := unverified["iss"].(string)

	// Pick the source whose provider issued the token. A source that can't
	// be resolved is authn's misconfiguration, never the caller's refusal.
	var source *sav1alpha1.SubjectTokenSource
	var keys resolvers.OIDCTokenKeys
	for i := range sources {
		k, err := resolvers.OIDCConfigTokenKeys(ctx, r.rc, sources[i].OIDCConfig)
		if err != nil {
			return failed(fmt.Errorf("resolving the OIDCConfig of the actor's subject-token source: %w", err))
		}
		if iss != "" && k.Issuer == iss {
			source, keys = &sources[i], k
			break
		}
	}
	if source == nil {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.DelegationNotAllowed, status.Refused(CauseDelegationNotAllowed,
			errors.New("the actor's ServiceAccount mapping lists no identity provider that issued this token"))
	}

	keySource := r.idpKeySource(keys.JWKSURI)
	claims := jwt.MapClaims{}
	_, err = jwt.NewParser(jwt.WithValidMethods(idpAlgorithms), jwt.WithIssuer(keys.Issuer),
		jwt.WithExpirationRequired(), jwt.WithLeeway(idpLeeway)).
		ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			return keySource.PublicKey(kid)
		})
	switch {
	case errors.Is(err, jwtutil.ErrKeyUnavailable):
		// The provider's keys couldn't be read: not the token's fault.
		return failed(fmt.Errorf("reading the identity provider's signing keys: %w", err))
	case errors.Is(err, jwt.ErrTokenExpired):
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.SubjectTokenExpired, subjectInvalid(fmt.Errorf("the subject token has expired: %w", err))
	case err != nil:
		return invalid(fmt.Errorf("the subject token didn't verify against its identity provider: %w", err))
	}
	aud, err := claims.GetAudience()
	if err != nil || !slices.ContainsFunc(aud, func(a string) bool { return slices.Contains(source.Audiences, a) }) {
		return invalid(errors.New("the subject token isn't for an audience the actor's subject-token source lists"))
	}
	expAt, err := claims.GetExpirationTime()
	if err != nil || expAt == nil {
		return invalid(errors.New("the subject token has no expiry"))
	}
	if time.Until(expAt.Time) < time.Second {
		return jwtutil.UserInfo{}, time.Time{}, nil, auditlog.SubjectTokenExpired, subjectInvalid(errors.New("the subject token is about to expire"))
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return invalid(errors.New("the subject token has no sub"))
	}
	preferred, ok := stringClaim(claims, "preferred_username")
	if !ok {
		return invalid(errors.New("the subject token's preferred_username isn't a string"))
	}
	groups, ok := stringListClaim(claims, "groups")
	if !ok {
		return invalid(errors.New("the subject token's groups aren't a list of strings"))
	}

	user := userinfo.NewDefaultUser(kubeutil.MakeDNS1123Compatible(preferred), "", groups, nil)
	user.Subject = userinfo.Subject{Issuer: keys.Issuer, ID: sub}
	person := jwtutil.UserInfo{Username: user.GetUserName(), Groups: user.GetGroups(), Principal: jwtutil.PrincipalHuman}

	lookup := r.opts.Lookup
	if lookup == nil {
		if lookup, err = kubeconfig.NewNameLookup(r.rc); err != nil {
			return failed(fmt.Errorf("building the name lookup: %w", err))
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
