package encode

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/plumbing/jwtutil"
)

// DefaultJwtDuration is the token lifetime used when a caller supplies none.
const DefaultJwtDuration = time.Hour * 8

type Extras struct {
	UserInfo      userinfo.Info
	JwtDuration   time.Duration
	JwtPrivateKey *rsa.PrivateKey
	JwtKeyID      string
	// CertNotAfter is the real expiry of the client certificate carried in the
	// same response. The token is clamped to it. Zero leaves it unclamped.
	CertNotAfter time.Time
}

// tokenDuration resolves the lifetime of the issued token: the requested
// duration, but never past the certificate shipped alongside it.
//
// The two are NOT the same knob even though one value configures both. The
// requested certificate duration is a wish; the signer grants
// min(requested, cluster-signing-duration, signer CA remaining life). Issuing a
// token for the requested duration would let a session outlive the credential
// it authenticates with — the user stays logged in while every user-scoped call
// fails with `x509: certificate has expired`, and there is no refresh endpoint
// to recover from it. Clamping makes the session end with the credential, so
// the user is sent back through login instead.
func tokenDuration(requested time.Duration, notAfter time.Time) time.Duration {
	if requested <= 0 {
		requested = DefaultJwtDuration
	}

	if notAfter.IsZero() {
		return requested
	}

	if remaining := time.Until(notAfter); remaining < requested {
		return remaining
	}

	return requested
}

// Success writes the login response. It builds the whole body (signing the
// token) before writing anything, so a non-nil error means nothing was sent
// and the caller must still reply with a failure. Once the body is built, a
// failure to write it means the client is gone; there is no one left to tell,
// so it is not returned.
func Success(w http.ResponseWriter, dat []byte, extras *Extras) (err error) {
	out := response{
		Data: dat,
	}

	if extras != nil {
		if nfo := extras.UserInfo; nfo != nil {
			out.User = &user{
				Username:    nfo.GetUserName(),
				DisplayName: nfo.GetExtensions().Get("name"),
				AvatarURL:   nfo.GetExtensions().Get("avatarUrl"),
			}
			out.Groups = nfo.GetGroups()

			if extras.JwtPrivateKey != nil {
				out.AccessToken, err = jwtutil.CreateToken(jwtutil.CreateTokenOptions{
					Username:   nfo.GetUserName(),
					Groups:     nfo.GetGroups(),
					Duration:   tokenDuration(extras.JwtDuration, extras.CertNotAfter),
					KeyID:      extras.JwtKeyID,
					PrivateKey: extras.JwtPrivateKey,
				})
				if err != nil {
					return err
				}
			}
		}
	}

	body, err := json.Marshal(&out)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
	return nil
}

type user struct {
	DisplayName string `json:"displayName"`
	Username    string `json:"username"`
	AvatarURL   string `json:"avatarURL"`
}

type response struct {
	AccessToken string          `json:"accessToken,omitempty"`
	User        *user           `json:"user,omitempty"`
	Groups      []string        `json:"groups,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}
