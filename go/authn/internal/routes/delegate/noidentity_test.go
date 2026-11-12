package delegate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/stretchr/testify/require"
)

// No log line of a delegation names the person or the service acting for
// them, whether the token is issued or refused: not the subject, its groups,
// the actor's ServiceAccount, its mapping or the actors before it (Diego,
// 2026-11-12). The audit record names them; session.id joins the two.
func TestDelegationLogsNoIdentity(t *testing.T) {
	const actorSA = "system:serviceaccount:" + logtest.Marker + "-ns:" + logtest.Marker + "-agent"
	review := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
		"status":{"authenticated":true,"audiences":["authn"],"user":{"username":"` + actorSA + `"}}}`
	mappingWith := func(delegation string) string {
		spec := fmt.Sprintf(`"serviceAccountRef":{"namespace":"%s-ns","name":"%s-agent"},"groups":["%s-group"]`,
			logtest.Marker, logtest.Marker, logtest.Marker)
		if delegation != "" {
			spec += `,"delegation":` + delegation
		}
		return `{"apiVersion":"serviceaccount.authn.krateo.io/v1alpha1","kind":"ServiceAccountList","items":[` +
			`{"metadata":{"name":"` + logtest.Marker + `-agent-identity","namespace":"krateo-system"},"spec":{` + spec + `}}]}`
	}
	k := newKeys(t)
	subject := func(t *testing.T, ttl time.Duration, act *jwtutil.Actor) string {
		t.Helper()
		tok, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
			Username: logtest.User, Groups: []string{logtest.Marker + "-group"}, Duration: ttl,
			KeyID: "current", PrivateKey: k.current, Act: act, Principal: jwtutil.PrincipalHuman,
		})
		require.NoError(t, err)
		return tok
	}
	portal := &jwtutil.Actor{Sub: logtest.Marker + "-portal", Principal: jwtutil.PrincipalAgent}

	for _, tc := range []struct {
		name         string
		review       string
		mappingsCode int
		mappings     string
		subject      func(t *testing.T) string
		grant        string // the form's grant_type, when not RFC 8693's
		code         int
	}{
		{name: "a grant type naming someone", mappings: mappingWith(`{"allowed":true}`), grant: logtest.Email,
			code: http.StatusBadRequest, subject: func(t *testing.T) string { return subject(t, time.Hour, nil) }},
		{name: "issued", mappings: mappingWith(`{"allowed":true}`), code: http.StatusOK,
			subject: func(t *testing.T) string { return subject(t, time.Hour, portal) }},
		{name: "actor not opted in", mappings: mappingWith(""), code: http.StatusForbidden,
			subject: func(t *testing.T) string { return subject(t, time.Hour, nil) }},
		{name: "chain too deep", mappings: mappingWith(`{"allowed":true,"maxDepth":1}`), code: http.StatusForbidden,
			subject: func(t *testing.T) string { return subject(t, time.Hour, portal) }},
		{name: "subject expired", mappings: mappingWith(`{"allowed":true}`), code: http.StatusUnauthorized,
			subject: func(t *testing.T) string { return subject(t, -time.Minute, nil) }},
		{name: "subject about to expire", mappings: mappingWith(`{"allowed":true}`), code: http.StatusUnauthorized,
			subject: func(t *testing.T) string { return subject(t, 500*time.Millisecond, portal) }},
		{name: "subject signed by another key", mappings: mappingWith(`{"allowed":true}`), code: http.StatusUnauthorized,
			subject: func(t *testing.T) string {
				tok, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{Username: logtest.User, Duration: time.Hour,
					KeyID: "current", PrivateKey: k.stranger})
				require.NoError(t, err)
				return tok
			}},
		{name: "actor has no mapping", mappings: strings.Replace(mappingWith(""), logtest.Marker+"-agent\"}", "other\"}", 1),
			code: http.StatusForbidden, subject: func(t *testing.T) string { return subject(t, time.Hour, nil) }},
		{name: "actor's mapping lookup fails", mappingsCode: http.StatusInternalServerError, code: http.StatusInternalServerError,
			subject: func(t *testing.T) string { return subject(t, time.Hour, nil) }},
		{name: "actor not authenticated", review: `{"kind":"TokenReview","status":{"authenticated":false,
			"error":"serviceaccounts \"` + logtest.Marker + `-agent\" not found"}}`, code: http.StatusForbidden,
			subject: func(t *testing.T) string { return subject(t, time.Hour, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.review == "" {
				tc.review = review
			}
			if tc.mappingsCode == 0 {
				tc.mappingsCode = http.StatusOK
			}
			rc, _ := apiserverWith(t, tc.review, tc.mappingsCode, tc.mappings)
			f := form(tc.subject(t))
			if tc.grant != "" {
				f.Set("grant_type", tc.grant)
			}
			req, logs := logtest.Request(httptest.NewRequest(http.MethodPost, Path, strings.NewReader(f.Encode())))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", "Bearer sa")
			rec := httptest.NewRecorder()
			k.route(rc).ServeHTTP(rec, req)

			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			logtest.NoIdentity(t, logs)
		})
	}
}
