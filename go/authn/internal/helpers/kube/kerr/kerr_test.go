package kerr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const who = "zz-sentinel-user"

func TestWrapNamesNoObject(t *testing.T) {
	secrets := schema.GroupResource{Resource: "secrets"}
	nested := &url.Error{Op: "Get", URL: "https://k8s/a", Err: &url.Error{Op: "parse",
		URL: "https://k8s/api/v1/namespaces/n/secrets/" + who + "-clientconfig", Err: errors.New("bad " + who)}}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"not found", apierrors.NewNotFound(secrets, who+"-clientconfig"), "reading the Secret: NotFound (404)"},
		{"forbidden", apierrors.NewForbidden(secrets, who+"-clientconfig", errors.New(`User "`+who+`" cannot get`)), "reading the Secret: Forbidden (403)"},
		{"wrapped", fmt.Errorf("x %q: %w", who, apierrors.NewConflict(secrets, who+"-clientconfig", errors.New("modified"))), "reading the Secret: Conflict (409)"},
		{"a webhook's own reason", &apierrors.StatusError{ErrStatus: metav1.Status{Code: 403,
			Reason: metav1.StatusReason(who + " may not have a session")}}, "reading the Secret: Forbidden (403)"},
		{"no reason, no code", &apierrors.StatusError{}, "reading the Secret: Unknown (0)"},
		{"connection refused", &url.Error{Op: "Get", URL: "https://k8s/api/v1/namespaces/n/secrets/" + who,
			Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}, "reading the Secret: dial: " + syscall.ECONNREFUSED.Error()},
		{"timed out", &url.Error{Op: "Get", URL: "https://k8s/" + who, Err: context.DeadlineExceeded}, "reading the Secret: the request timed out"},
		{"nested URLs", nested, "reading the Secret: the request failed in transport"},
		{"other", fmt.Errorf("invalid resource name %q", who+"/x"), "reading the Secret: request failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Wrap("reading the Secret", tc.err)
			assert.Equal(t, tc.want, err.Error())
			assert.NotContains(t, err.Error(), "zz-sentinel")
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

func TestWrapKeepsTheAPIStatus(t *testing.T) {
	err := Wrap("reading the User", apierrors.NewNotFound(schema.GroupResource{Resource: "users"}, who))
	assert.True(t, apierrors.IsNotFound(err))
	var st apierrors.APIStatus
	require.True(t, errors.As(err, &st))
	assert.EqualValues(t, 404, st.Status().Code)

	assert.NoError(t, Wrap("x", nil))
	assert.NoError(t, Described("x", nil))
}

func TestDescribedIsTheWholeText(t *testing.T) {
	orig := fmt.Errorf(`csr "CORP\\%s-abcde" was deleted`, who)
	err := Described("waiting for the certificate: the CSR was deleted", orig)
	assert.Equal(t, "waiting for the certificate: the CSR was deleted", err.Error())
	assert.ErrorIs(t, err, orig)
}
