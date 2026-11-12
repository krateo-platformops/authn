package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/logtest"
	"github.com/krateo-platformops/authn/internal/logtest/gentest"
	"github.com/krateo-platformops/authn/internal/status"
	"github.com/stretchr/testify/require"
)

// No log line of an OAuth login names the user, whether it succeeds, is
// refused or fails: not the RESTAction's answer, the username, subject, email
// or groups (Diego, 2026-11-12).
func TestOAuthLoginLogsNoIdentity(t *testing.T) {
	full := fmt.Sprintf(`{"status":{"subject":%q,"name":"%s Name","preferredUsername":%q,"email":%q,"groups":["%s-group"],"avatarURL":"https://x.example/%s"}}`,
		logtest.Subject, logtest.Marker, logtest.User, logtest.Email, logtest.Marker, logtest.Marker)
	cases := []struct {
		name   string
		answer string
		err    error
		code   int
	}{
		{name: "success", answer: full, code: http.StatusOK},
		{name: "no subject", answer: fmt.Sprintf(`{"status":{"name":"%s Name","preferredUsername":%q,"email":%q}}`,
			logtest.Marker, logtest.User, logtest.Email), code: http.StatusInternalServerError},
		{name: "unusable answer", answer: fmt.Sprintf(`{"status":{"subject":%q,"name":%q,"preferredUsername":%q,"groups":"%s-group"}}`,
			logtest.Subject, logtest.User, logtest.User, logtest.Marker), code: http.StatusInternalServerError},
		{name: "name guard refuses", answer: full, code: http.StatusForbidden, err: kubeconfig.Refused(kubeconfig.RefusalProvisioned,
			status.RefusedPrivately(status.CauseUsernameUnavailable, errors.New("the username isn't available to this identity"),
				errors.New("the username was provisioned by an administrator as a basic User or ServiceAccount mapping")))},
		{name: "issuance fails", answer: full, code: http.StatusInternalServerError, err: errors.New("updating the credential Secret: Conflict (409)")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, logs := oauthLoginWith(t, tc.answer, true, &fakeGenerator{err: tc.err})
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			if rec.Code == http.StatusOK {
				require.Contains(t, logs.String(), gentest.Line, "the route hands the generator its logger")
			}
			logtest.NoIdentity(t, logs)
		})
	}
}
