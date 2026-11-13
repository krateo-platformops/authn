package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oidcv1alpha1 "github.com/krateo-platformops/authn/apis/authn/oidc/v1alpha1"
	"github.com/krateo-platformops/authn/apis/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An OIDCConfig that maps identities through a RESTAction is flagged, so an
// exchange can refuse it; its keys still resolve, so the exchange knows it
// was the token's provider.
func TestTokenKeysFlagARESTActionMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": discoveredIssuer, "jwks_uri": "https://idp.example/certs"})
	}))
	t.Cleanup(srv.Close)
	cfg := &oidcv1alpha1.OIDCConfig{}
	cfg.Spec.DiscoveryURL = srv.URL

	got, err := tokenKeys(context.Background(), cfg, fetchDiscovery)
	require.NoError(t, err)
	assert.False(t, got.MapsThroughRESTAction)

	cfg.Spec.RESTActionRef = &core.ObjectRef{Name: "userinfo", Namespace: "krateo-system"}
	got, err = tokenKeys(context.Background(), cfg, fetchDiscovery)
	require.NoError(t, err)
	assert.True(t, got.MapsThroughRESTAction)
	assert.Equal(t, discoveredIssuer, got.Issuer)
}

// The discovery document is fetched once per DiscoveryTTL, a failure once per
// DiscoveryFailureTTL, and a fetch the caller's own context cut short isn't
// remembered at all.
func TestTokenKeysResolverCachesDiscovery(t *testing.T) {
	var fetches atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": discoveredIssuer, "jwks_uri": "https://idp.example/certs"})
	}))
	t.Cleanup(srv.Close)

	clock := time.Now()
	r := NewTokenKeysResolver(nil)
	r.now = func() time.Time { return clock }
	ctx := context.Background()

	for range 3 {
		doc, err := r.discovery(ctx, srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example/certs", doc.JWKSURI)
	}
	assert.EqualValues(t, 1, fetches.Load(), "a fresh document is served from the cache")

	down.Store(true)
	clock = clock.Add(DiscoveryTTL - time.Second)
	_, err := r.discovery(ctx, srv.URL)
	require.NoError(t, err, "still fresh")
	assert.EqualValues(t, 1, fetches.Load())

	clock = clock.Add(2 * time.Second)
	for range 3 {
		_, err = r.discovery(ctx, srv.URL)
		assert.ErrorIs(t, err, ErrDiscoveryFailed)
	}
	assert.EqualValues(t, 2, fetches.Load(), "a failure is remembered too")

	down.Store(false)
	clock = clock.Add(DiscoveryFailureTTL + time.Second)
	_, err = r.discovery(ctx, srv.URL)
	require.NoError(t, err, "the provider is back once the failure lapses")
	assert.EqualValues(t, 3, fetches.Load())

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	other := srv.URL + "/other"
	_, err = r.discovery(canceled, other)
	require.Error(t, err)
	_, err = r.discovery(ctx, other)
	require.NoError(t, err, "a canceled fetch isn't cached as the provider's failure")
}

// A discovery document past the cap isn't read into memory.
func TestDiscoveryBodyIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + discoveredIssuer + `","pad":"` + strings.Repeat("x", maxDiscoveryBody) + `"}`))
	}))
	t.Cleanup(srv.Close)
	_, err := fetchDiscovery(context.Background(), srv.URL)
	assert.ErrorIs(t, err, ErrDiscoveryFailed)
	assert.Contains(t, err.Error(), "more than")

	exact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := `{"issuer":"` + discoveredIssuer + `","pad":"`
		_, _ = w.Write([]byte(body + strings.Repeat("x", maxDiscoveryBody-len(body)-2) + `"}`))
	}))
	t.Cleanup(exact.Close)
	doc, err := fetchDiscovery(context.Background(), exact.URL)
	require.NoError(t, err, "a document of exactly the cap is read")
	assert.Equal(t, discoveredIssuer, doc.Issuer)
}
