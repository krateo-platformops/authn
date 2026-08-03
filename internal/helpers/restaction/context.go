package restaction

import (
	"context"

	xcontext "github.com/krateo-platformops/plumbing/context"
)

// MergeRequestContext returns a context rooted at reqCtx (so it carries the
// inbound request's OpenTelemetry span, deadlines and cancellation) while
// copying forward the long-lived values that the outbound snowplow RESTAction
// call depends on from baseCtx:
//
//   - the authn access token (plumbing accessToken key),
//   - the RESTAction "username" value,
//   - the RESTAction "snowplowURL" value.
//
// This is the bridge that lets the snowplow call be both traced (parented to
// the inbound request span via reqCtx) AND authenticated (the token/username/
// snowplowURL are NOT dropped). Without it, switching the outbound call to
// req.Context() would break snowplow auth.
func MergeRequestContext(reqCtx, baseCtx context.Context) context.Context {
	out := reqCtx

	if tok, ok := xcontext.AccessToken(baseCtx); ok {
		out = xcontext.BuildContext(out, xcontext.WithAccessToken(tok))
	}

	if v := baseCtx.Value(RestActionContextKey("username")); v != nil {
		out = context.WithValue(out, RestActionContextKey("username"), v)
	}

	if v := baseCtx.Value(RestActionContextKey("snowplowURL")); v != nil {
		out = context.WithValue(out, RestActionContextKey("snowplowURL"), v)
	}

	return out
}
