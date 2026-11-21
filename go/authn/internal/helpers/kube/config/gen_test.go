package config

import (
	"crypto/x509"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/configtest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeSigner is configtest.FakeSigner.
func fakeSigner(t *testing.T) (*fake.Clientset, *[]string) { return configtest.FakeSigner(t) }

// Two issuances for the same user at once, such as a normal login and a
// step-up, each get their own CSR and certificate. Neither deletes the
// other's request, and both CSRs are cleaned up afterwards.
func TestConcurrentIssuanceUsesDistinctCSRs(t *testing.T) {
	cli, created := fakeSigner(t)

	type result struct {
		leaf *x509.Certificate
		err  error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i, groups := range [][]string{{"devs"}, {"devs", "krateo:loa:2"}} {
		wg.Add(1)
		go func(i int, groups []string) {
			defer wg.Done()
			_, _, leaf, err := generateClientCertAndKey(cli, zerolog.Nop(), generateClientCertAndKeyOpts{
				duration: 15 * time.Minute, userID: "1", username: "alice", groups: groups,
			})
			results[i] = result{leaf, err}
		}(i, groups)
	}
	wg.Wait()

	for i, r := range results {
		require.NoError(t, r.err, "issuance %d", i)
		assert.Equal(t, "alice", r.leaf.Subject.CommonName)
	}
	assert.Equal(t, []string{"devs"}, results[0].leaf.Subject.Organization)
	assert.Equal(t, []string{"devs", "krateo:loa:2"}, results[1].leaf.Subject.Organization)

	require.Len(t, *created, 2)
	assert.NotEqual(t, (*created)[0], (*created)[1], "each issuance has its own CSR")
	for _, name := range *created {
		assert.Regexp(t, `^alice-\d{5}$`, name)
	}

	left, err := cli.CertificatesV1().CertificateSigningRequests().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, left.Items, "used CSRs are deleted")
}
