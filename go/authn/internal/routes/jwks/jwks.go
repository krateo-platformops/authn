package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/krateo-platformops/authn/internal/routes"
)

// Path is the conventional discovery location agentgateway (and most JWKS
// consumers) fetch the key set from.
const Path = "/.well-known/jwks.json"

// jwk is a single JSON Web Key describing the public half of authn's RSA
// signing key. Only the fields required to verify an RS256 signature are set.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// Endpoint serves the JWKS derived from the given RSA public key and key ID at
// GET /.well-known/jwks.json. Validators such as agentgateway select the key
// whose "kid" matches the token header, so kid must equal the KeyID authn signs
// with. The document is computed once at construction time and served verbatim.
func Endpoint(pub *rsa.PublicKey, kid string) routes.Route {
	set := jwkSet{
		Keys: []jwk{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: kid,
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}

	body, err := json.Marshal(set)
	if err != nil {
		// Marshalling a struct of strings cannot fail; guard anyway so a
		// misconfiguration surfaces as an empty body rather than a panic.
		body = []byte(`{"keys":[]}`)
	}

	return &jwksRoute{body: body}
}

var _ routes.Route = (*jwksRoute)(nil)

type jwksRoute struct {
	body []byte
}

func (r *jwksRoute) Name() string { return "jwks" }

func (r *jwksRoute) Pattern() string { return Path }

func (r *jwksRoute) Method() string { return http.MethodGet }

func (r *jwksRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, _ *http.Request) {
		wri.Header().Set("Content-Type", "application/json")
		wri.Header().Set("Cache-Control", "public, max-age=300")
		wri.WriteHeader(http.StatusOK)
		wri.Write(r.body)
	}
}
