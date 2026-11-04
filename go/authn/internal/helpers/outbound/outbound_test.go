package outbound

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A redirect is never followed: whatever the status, the destination receives
// no request at all, so neither the Authorization header nor the body (which
// a 307/308 would resend) reaches it. Asserted on the destination, not on
// CheckRedirect being set: a set CheckRedirect can still permit.
func TestClientRefusesEveryRedirect(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			reached := 0
			dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++ }))
			t.Cleanup(dest.Close)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, dest.URL+"/steal", code)
			}))
			t.Cleanup(origin.Close)

			req, err := http.NewRequest(http.MethodPost, origin.URL, strings.NewReader("client_secret=s3cret"))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer user-token")
			resp, err := Client().Do(req)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrRedirectRefused), "%v", err)
			assert.Zero(t, reached, "the redirect target was never contacted")
		})
	}
}

func TestClientLeavesDefaultClientAlone(t *testing.T) {
	_ = Client()
	assert.Nil(t, http.DefaultClient.CheckRedirect)
}
