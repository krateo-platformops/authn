package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/krateo-platformops/authn/internal/routes"
)

// Path is the health probe route. Exported so instrumentation (e.g. OTel
// tracing filters) can exclude it from probe noise.
const Path = "/health"

func Check(healthy *int32, version string, serviceName string) routes.Route {
	return &healthRoute{
		healthy:     healthy,
		version:     version,
		serviceName: serviceName,
	}
}

var _ routes.Route = (*healthRoute)(nil)

type healthRoute struct {
	healthy     *int32
	version     string
	serviceName string
}

func (r *healthRoute) Name() string {
	return "health"
}

func (r *healthRoute) Pattern() string {
	return Path
}

func (r *healthRoute) Method() string {
	return http.MethodGet
}

func (r *healthRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, _ *http.Request) {
		if atomic.LoadInt32(r.healthy) == 1 {
			data := map[string]string{
				"name":    r.serviceName,
				"version": r.version,
			}

			wri.Header().Set("Content-Type", "application/json")
			wri.WriteHeader(http.StatusOK)
			json.NewEncoder(wri).Encode(data)
			return
		}
		wri.WriteHeader(http.StatusServiceUnavailable)
	}
}
