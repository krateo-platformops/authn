package kerr

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestWrapNamesNoObject(t *testing.T) {
	secrets := schema.GroupResource{Resource: "secrets"}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"not found", apierrors.NewNotFound(secrets, "alice-clientconfig"), "reading the Secret: NotFound (404)"},
		{"forbidden", apierrors.NewForbidden(secrets, "alice-clientconfig", errors.New(`User "system:serviceaccount:x:authn" cannot get`)), "reading the Secret: Forbidden (403)"},
		{"wrapped", fmt.Errorf("x %q: %w", "alice", apierrors.NewConflict(secrets, "alice-clientconfig", errors.New("modified"))), "reading the Secret: Conflict (409)"},
		{"no answer", &url.Error{Op: "Get", URL: "https://k8s/api/v1/namespaces/n/secrets/alice-clientconfig", Err: errors.New("connection refused")}, "reading the Secret: Get request: connection refused"},
		{"other", fmt.Errorf("invalid resource name %q", "alice/x"), "reading the Secret: request failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Wrap("reading the Secret", tc.err)
			assert.Equal(t, tc.want, err.Error())
			assert.NotContains(t, err.Error(), "alice")
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

func TestWrapKeepsTheAPIStatus(t *testing.T) {
	err := Wrap("reading the User", apierrors.NewNotFound(schema.GroupResource{Resource: "users"}, "alice"))
	assert.True(t, apierrors.IsNotFound(err))
	var st apierrors.APIStatus
	require.True(t, errors.As(err, &st))
	assert.EqualValues(t, 404, st.Status().Code)

	assert.NoError(t, Wrap("x", nil))
	assert.NoError(t, Redact("x", nil))
}

func TestRedactReplacesTheNames(t *testing.T) {
	orig := fmt.Errorf("csr %q was deleted", "alice-x7k2p")
	err := Redact("waiting for the certificate", orig, "alice-x7k2p", "")
	assert.Equal(t, `waiting for the certificate: csr "<name>" was deleted`, err.Error())
	assert.ErrorIs(t, err, orig)
}
