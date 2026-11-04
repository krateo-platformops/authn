package restaction

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krateo-platformops/authn/apis/core"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const userToken = "gho_user-idp-token" // gitleaks:allow (a test value)

func snowplowCtx(url string) context.Context {
	ctx := xcontext.BuildContext(context.Background(), xcontext.WithAccessToken("authn-jwt"))
	return context.WithValue(ctx, RestActionContextKey("snowplowURL"), url)
}

// The user's IdP token goes to snowplow in the body of POST /call/read, never
// in the URL, where gateways, proxies and trace spans record it.
func TestResolveSendsTheTokenInTheBody(t *testing.T) {
	var got struct {
		method, path, rawQuery, ctype, auth string
		body                                map[string]map[string]string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.rawQuery = r.Method, r.URL.Path, r.URL.RawQuery
		got.ctype, got.auth = r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(b, &got.body), string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"RESTAction","status":{"name":"Alice","groups":["devs"]}}`)
	}))
	t.Cleanup(srv.Close)

	out, err := Resolve(snowplowCtx(srv.URL), &core.ObjectRef{Name: "gh user&x=1", Namespace: "krateo-system"}, userToken)
	require.NoError(t, err)
	assert.Equal(t, "Alice", out["name"])

	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/call/read", got.path)
	assert.NotContains(t, got.rawQuery, userToken, "the token is in no URL")
	assert.NotContains(t, got.rawQuery, "extras")
	assert.Contains(t, got.rawQuery, "name=gh+user%26x%3D1", "the addressing is escaped")
	assert.Contains(t, got.rawQuery, "apiVersion=templates.krateo.io%2Fv1")
	assert.Contains(t, got.rawQuery, "resource=restactions")
	assert.Contains(t, got.rawQuery, "namespace=krateo-system")
	assert.Equal(t, "application/json", got.ctype)
	assert.Equal(t, "Bearer authn-jwt", got.auth, "snowplow is called as authn")
	assert.Equal(t, map[string]map[string]string{"extras": {"token": userToken}}, got.body)
}

// snowplow's own answer is kept: its code and reason reach the caller, its
// message (which may name stage endpoints) only the log.
func TestResolveKeepsSnowplowsAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Timeout","message":"stage userInfo: https://api.internal.example/user timed out","code":504}`)
	}))
	t.Cleanup(srv.Close)

	_, err := Resolve(snowplowCtx(srv.URL), &core.ObjectRef{Name: "gh", Namespace: "krateo-system"}, userToken)
	var se *SnowplowError
	require.True(t, errors.As(err, &se), "%v", err)
	assert.Equal(t, http.StatusGatewayTimeout, se.Code)
	assert.Equal(t, "Timeout", se.Reason)
	assert.Contains(t, se.Message, "timed out")

	ce := Failed(err)
	assert.Equal(t, http.StatusInternalServerError, ce.Code)
	assert.Equal(t, CauseRESTActionFailed, ce.Cause)
	assert.Equal(t, "the RESTAction could not be resolved: snowplow answered 504 Timeout", ce.Error())
	assert.False(t, strings.Contains(ce.Error(), "api.internal.example"), "snowplow's message stays in the log")
	assert.Equal(t, err, ce.Private)
}

func TestFailedWithoutAnAnswer(t *testing.T) {
	ce := Failed(errors.New("dial tcp 10.0.0.9:8081: connection refused"))
	assert.Equal(t, "the RESTAction could not be resolved", ce.Error())
	assert.NotContains(t, ce.Error(), "10.0.0.9")
}
