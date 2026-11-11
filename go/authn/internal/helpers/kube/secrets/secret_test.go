package secrets

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func answering(t *testing.T, code int, body string) *rest.Config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}
}

// Create and Update return the apiserver's status and decode the stored
// Secret, uid included, into the one they were given. An answer to a done
// write that can't be decoded is still a done write: the status is known, the
// uid isn't, and there is no error.
func TestWritesReportTheAnswer(t *testing.T) {
	stored := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"ns","uid":"uid-1","resourceVersion":"4"}}`
	for _, tc := range []struct {
		name    string
		write   func(context.Context, *rest.Config, *corev1.Secret) (int, error)
		code    int
		body    string
		wantUID string
		wantErr bool
	}{
		{"create", Create, 201, stored, "uid-1", false},
		{"update", Update, 200, stored, "uid-1", false},
		{"create, undecodable answer", Create, 201, `{not json`, "", false},
		{"create refused", Create, 403, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns"}}
			code, err := tc.write(context.Background(), answering(t, tc.code, tc.body), sec)
			assert.Equal(t, tc.code, code)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantUID, string(sec.UID))
		})
	}
}
