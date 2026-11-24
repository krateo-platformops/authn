package delegate

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	kubesecrets "github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/routes/auth/serviceaccount"
	"github.com/krateo-platformops/authn/internal/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// ClientAssertionType is RFC 7523's identifier (§2.2) of a client that
	// authenticates with a JWT it signed (private_key_jwt).
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// maxAssertionLife is the furthest ahead a client assertion may expire,
	// and so the longest its jti is remembered.
	maxAssertionLife = 10 * time.Minute
	// assertionLeeway absorbs clock skew with the client.
	assertionLeeway = 10 * time.Second
	// maxJTI bounds what one remembered assertion holds.
	maxJTI = 256
)

const (
	// CauseClientAssertionInvalid: no client assertion, or one that doesn't
	// authenticate a service (RFC 6749's invalid_client).
	CauseClientAssertionInvalid status.CauseType = "ClientAssertionInvalid" // 401
	// CauseClientKeyUnavailable: the mapping's registered certificate can't be
	// read (spec.clientAssertion.certificateSecretName).
	CauseClientKeyUnavailable status.CauseType = "ClientKeyUnavailable" // 500
)

// assertionAlgorithms are the asymmetric algorithms a client may sign with.
// The key's own type decides among them: an RSA key never verifies an ES256
// assertion, and no algorithm verifies with a public key as a shared secret.
var assertionAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// seenJTIs remembers the client assertions already used until they expire, so
// that this replica takes each one once (RFC 7523 §3, "jti"). The zero value is
// ready. Only assertions that verified are remembered, so what it holds is
// bounded by what registered services send.
type seenJTIs struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// first reports whether id is used for the first time, and remembers it until
// it can no longer verify.
func (s *seenJTIs) first(id string, exp, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, until := range s.seen {
		if now.After(until) {
			delete(s.seen, k)
		}
	}
	if _, used := s.seen[id]; used {
		return false
	}
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	s.seen[id] = exp.Add(assertionLeeway)
	return true
}

// authenticateAssertion authenticates the actor by its client assertion (RFC
// 7523 §2.2, §3) and returns its mapping. The assertion's iss and sub are the
// mapping's name, it is addressed to authn (the audience a ServiceAccount token
// is), it expires within maxAssertionLife, it is used once, and it is signed
// with the key whose certificate the mapping registers
// (spec.clientAssertion).
//
// Every refusal of the assertion is one answer, so it doesn't say which
// services exist or sign: the reason is for the log.
func (r *route) authenticateAssertion(req *http.Request) (*sav1alpha1.ServiceAccount, error) {
	refuse := func(why error) (*sav1alpha1.ServiceAccount, error) {
		return nil, status.CauseError{Code: http.StatusUnauthorized, Cause: CauseClientAssertionInvalid,
			Err: errors.New("the client assertion is missing or doesn't authenticate a service"), Private: why}
	}
	if req.Header.Get("Authorization") != "" {
		// RFC 6749 §2.3: one authentication method per request.
		return nil, status.BadRequest(status.CauseInvalidRequestBody,
			errors.New("authenticate with the client assertion only, with no Authorization header"))
	}
	form := req.PostForm // parsed by readExchange
	if len(form["client_assertion"]) != 1 || len(form["client_assertion_type"]) != 1 || form.Get("client_assertion_type") != ClientAssertionType {
		return refuse(fmt.Errorf("one client_assertion of type %s is required", ClientAssertionType))
	}
	assertion := form.Get("client_assertion")

	// The name is read before the signature is checked, to find the key to
	// check it with. Nothing else is taken from it until it verifies.
	var unverified jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(assertion, &unverified); err != nil {
		return refuse(err)
	}
	name := unverified.Issuer
	if len(validation.IsDNS1123Subdomain(name)) > 0 {
		return refuse(errors.New("iss isn't a mapping's name"))
	}
	if ids := form["client_id"]; len(ids) > 1 || (len(ids) == 1 && ids[0] != name) {
		return refuse(errors.New("client_id isn't iss"))
	}

	mapping, err := resolvers.ServiceAccountMappingGet(r.rc, name)
	switch {
	case apierrors.IsNotFound(err):
		return refuse(errors.New("no mapping has that name"))
	case err != nil:
		return nil, status.Failed(serviceaccount.CauseMappingLookupFailed, err)
	case mapping.Spec.ClientAssertion == nil:
		return refuse(errors.New("the mapping registers no client assertion key"))
	}
	key, err := r.registeredKey(req.Context(), mapping)
	if err != nil {
		return nil, status.FailedPrivately(CauseClientKeyUnavailable,
			errors.New("the service's registered certificate couldn't be read"), err)
	}

	var claims jwt.RegisteredClaims
	_, err = jwt.NewParser(jwt.WithValidMethods(assertionAlgorithms), jwt.WithIssuer(name), jwt.WithSubject(name),
		jwt.WithAudience(r.opts.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(assertionLeeway)).
		ParseWithClaims(assertion, &claims, func(*jwt.Token) (any, error) { return key, nil })
	if err != nil {
		return refuse(err)
	}
	now := time.Now()
	switch {
	case claims.ExpiresAt.Sub(now) > maxAssertionLife:
		return refuse(fmt.Errorf("it expires more than %s ahead", maxAssertionLife))
	case claims.ID == "" || len(claims.ID) > maxJTI:
		return refuse(fmt.Errorf("it has no jti of at most %d bytes", maxJTI))
	case !r.jtis.first(name+"/"+claims.ID, claims.ExpiresAt.Time, now):
		return refuse(errors.New("it was used before"))
	}
	return mapping, nil
}

// registeredKey is the public key of the certificate the mapping registers,
// which must be valid now. It is read on every call, so a rotation needs
// nothing else.
func (r *route) registeredKey(ctx context.Context, mapping *sav1alpha1.ServiceAccount) (crypto.PublicKey, error) {
	sec, err := kubesecrets.Get(ctx, r.rc, &core.SecretKeySelector{
		Name: mapping.Spec.ClientAssertion.CertificateSecretName, Namespace: mapping.Namespace})
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(sec.Data[corev1.TLSCertKey])
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("its %s holds no certificate", corev1.TLSCertKey)
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("its %s: %w", corev1.TLSCertKey, err)
	}
	if now := time.Now(); now.Before(crt.NotBefore) || now.After(crt.NotAfter) {
		return nil, errors.New("its certificate isn't valid now")
	}
	return crt.PublicKey, nil
}
