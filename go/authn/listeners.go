package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/rs/zerolog"
)

// listenerHandlers builds the two listeners' handlers. The public one serves
// buildRoutes; the internal one serves only what in-cluster services call
// (buildInternalRoutes), and the public one never serves its paths: whether a
// username is held is decided in-cluster, never on a public surface.
// TestListenersServeTheirOwnSurface pins both.
func listenerHandlers(o routeOptions, log zerolog.Logger) (public, internal http.Handler, err error) {
	all, err := buildRoutes(o)
	if err != nil {
		return nil, nil, err
	}
	return auditlog.Middleware(routes.Serve(all, log)),
		auditlog.Middleware(routes.Serve(buildInternalRoutes(o), log)), nil
}

// newServers builds the public server on publicPort and the internal one on
// internalPort, each with its own handler. The two must not share a port: the
// internal listener has its own Service, which no public route references.
func newServers(public, internal http.Handler, publicPort, internalPort int) (*http.Server, *http.Server, error) {
	if publicPort == internalPort {
		return nil, nil, fmt.Errorf("the internal listener must not share the public port %d", publicPort)
	}
	return &http.Server{
			Addr:         fmt.Sprintf(":%d", publicPort),
			Handler:      public,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 50 * time.Second,
			IdleTimeout:  30 * time.Second,
		}, &http.Server{
			Addr:         fmt.Sprintf(":%d", internalPort),
			Handler:      internal,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 20 * time.Second,
			IdleTimeout:  30 * time.Second,
		}, nil
}

// shutdownServers stops every server at once: each stops accepting and drains
// within ctx, concurrently, so one draining never keeps another accepting. It
// returns every server's error.
func shutdownServers(ctx context.Context, servers ...*http.Server) error {
	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		s.SetKeepAlivesEnabled(false)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Shutdown(ctx); err != nil {
				errs[i] = fmt.Errorf("%s: %w", s.Addr, err)
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}
