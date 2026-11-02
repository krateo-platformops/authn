package jwks

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strings"

	"github.com/krateo-platformops/plumbing/jwtutil"
)

// ParsePreviousKeys reads the verification-only keys of a key rotation from
// spec, a comma-separated list of kid=path (the JWT_PREVIOUS_KEYS format the
// chart writes). Each file holds a PEM RSA key: the retired private key as it
// sat in its Secret, or just its public half. Only the public key is kept.
//
// A previous key that can't be used is a configuration error, never skipped:
// an empty kid or path, a duplicate kid, the current kid, an unreadable or
// unparseable file, or the current signing key itself.
func ParsePreviousKeys(spec, currentKID string, current *rsa.PublicKey) ([]Key, error) {
	var keys []Key
	seen := map[string]bool{currentKID: true}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kid, path, ok := strings.Cut(entry, "=")
		kid, path = strings.TrimSpace(kid), strings.TrimSpace(path)
		if !ok || kid == "" || path == "" {
			return nil, fmt.Errorf("previous key %q: want kid=path", entry)
		}
		if seen[kid] {
			if kid == currentKID {
				return nil, fmt.Errorf("previous key %q: kid is the current signing key's", kid)
			}
			return nil, fmt.Errorf("previous key %q: kid listed twice", kid)
		}
		seen[kid] = true

		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("previous key %q: %w", kid, err)
		}
		pub, err := publicKeyFromPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("previous key %q (%s): %w", kid, path, err)
		}
		if current != nil && pub.Equal(current) {
			return nil, fmt.Errorf("previous key %q is the current signing key under another kid", kid)
		}
		keys = append(keys, Key{KID: kid, Pub: pub})
	}
	return keys, nil
}

// publicKeyFromPEM accepts a PEM RSA private key (PKCS#1 or PKCS#8) or public
// key (PKIX or PKCS#1) and returns the public key.
func publicKeyFromPEM(raw []byte) (*rsa.PublicKey, error) {
	if priv, err := jwtutil.ParseRSAPrivateKeyFromPEM(raw); err == nil {
		return &priv.PublicKey, nil
	}
	pub, err := jwtutil.ParseRSAPublicKeyFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("not a PEM RSA private or public key: %w", err)
	}
	return pub, nil
}
