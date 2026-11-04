// Package outbound is the HTTP client for every call authn makes to another
// service: the IdP's token, UserInfo and discovery endpoints, and snowplow.
// Each of them carries a credential (the client secret, an authorization
// code and PKCE verifier, the user's access token, authn's own JWT), so the
// client refuses every redirect.
//
// net/http's own protection is not enough. It drops Authorization only when
// a redirect leaves for a host that is neither the same hostname nor a
// subdomain of it, so a hop to sub.idp.example or to another port keeps it,
// and a 307/308 resends the request body, with the client secret or the
// user's token in it, to wherever Location points.
package outbound

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/krateo-platformops/authn/internal/telemetry"
)

// ErrRedirectRefused is wrapped by the error of a call whose answer was a
// redirect: the redirect was not followed, and nothing was sent to it.
var ErrRedirectRefused = errors.New("redirect refused")

// Client returns the client to call another service with: telemetry's (traced
// when tracing is on) with every redirect refused. It is a new client each
// time, so it never changes http.DefaultClient.
func Client() *http.Client {
	base := telemetry.HTTPClient()
	return &http.Client{
		Transport:     base.Transport,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
		CheckRedirect: refuseRedirects,
	}
}

func refuseRedirects(req *http.Request, via []*http.Request) error {
	from := ""
	if len(via) > 0 {
		from = via[len(via)-1].URL.Host
	}
	return fmt.Errorf("%w: %s answered a redirect to %s", ErrRedirectRefused, from, req.URL.Host)
}
