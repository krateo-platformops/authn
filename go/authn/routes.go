package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/routes/auth/basic"
	"github.com/krateo-platformops/authn/internal/routes/auth/ldap"
	"github.com/krateo-platformops/authn/internal/routes/auth/oauth"
	"github.com/krateo-platformops/authn/internal/routes/auth/oidc"
	"github.com/krateo-platformops/authn/internal/routes/auth/serviceaccount"
	"github.com/krateo-platformops/authn/internal/routes/auth/strategies"
	"github.com/krateo-platformops/authn/internal/routes/health"
	"github.com/krateo-platformops/authn/internal/routes/jwks"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"k8s.io/client-go/rest"
)

// routeOptions is what the HTTP surface needs from main.
type routeOptions struct {
	RestConfig             *rest.Config
	Generator              kubeconfig.Generator
	PrivateKey             *rsa.PrivateKey
	KeyID                  string
	JwtDuration            time.Duration
	ServiceAccountAudience string
	SelfUsername           string
	SnowplowURL            string
	Healthy                *int32
	Version                string
	ServiceName            string
}

// buildRoutes returns every route authn serves. It is the whole HTTP surface:
// TestPublicSurface (routes_test.go) pins this list and checks that no request
// without a successful login gets key material back.
func buildRoutes(o routeOptions) ([]routes.Route, error) {
	all := []routes.Route{}
	all = append(all, strategies.List(o.RestConfig))
	all = append(all, health.Check(o.Healthy, o.Version, o.ServiceName))
	all = append(all, jwks.Endpoint(&o.PrivateKey.PublicKey, o.KeyID))

	all = append(all, basic.Login(o.RestConfig, basic.LoginOptions{
		KubeconfigGenerator: o.Generator,
		JwtDuration:         o.JwtDuration,
		JwtPrivateKey:       o.PrivateKey,
		JwtKeyID:            o.KeyID,
	}))

	// Kubernetes intra-service auth: backend services exchange their own (audience-bound)
	// ServiceAccount token (validated via TokenReview) for an authn JWT + clientconfig.
	all = append(all, serviceaccount.Login(o.RestConfig, serviceaccount.LoginOptions{
		KubeconfigGenerator: o.Generator,
		JwtDuration:         o.JwtDuration,
		JwtPrivateKey:       o.PrivateKey,
		JwtKeyID:            o.KeyID,
		Audience:            o.ServiceAccountAudience,
	}))

	all = append(all, ldap.Login(o.RestConfig, ldap.LoginOptions{
		KubeconfigGenerator: o.Generator,
		JwtDuration:         o.JwtDuration,
		JwtPrivateKey:       o.PrivateKey,
		JwtKeyID:            o.KeyID,
	}))

	accessToken, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
		Username:   o.SelfUsername,
		Groups:     []string{"authn"},
		KeyID:      o.KeyID,
		PrivateKey: o.PrivateKey,
		Duration:   time.Hour * 8760, // 1 year,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot create jwt token for %s: %w", o.SelfUsername, err)
	}

	// The RESTAction enrichment shared by the oauth, oidc and step-up logins:
	// snowplow runs it as authn's own identity.
	restActionContext := func() context.Context {
		return xcontext.BuildContext(context.Background(),
			xcontext.WithAccessToken(accessToken),
			func(ctx context.Context) context.Context {
				ctx = context.WithValue(ctx,
					restaction.RestActionContextKey("username"), o.SelfUsername)
				return context.WithValue(ctx,
					restaction.RestActionContextKey("snowplowURL"), o.SnowplowURL)
			},
		)
	}

	all = append(all, oauth.Login(restActionContext(), o.RestConfig, oauth.LoginOptions{
		KubeconfigGenerator: o.Generator,
		JwtDuration:         o.JwtDuration,
		JwtPrivateKey:       o.PrivateKey,
		JwtKeyID:            o.KeyID,
	}))

	all = append(all, oidc.Login(restActionContext(), o.RestConfig, oidc.LoginOptions{
		KubeconfigGenerator: o.Generator,
		JwtDuration:         o.JwtDuration,
		JwtPrivateKey:       o.PrivateKey,
		JwtKeyID:            o.KeyID,
	}))

	// Step-up (#49): a short-lived krateo:loa:2 credential for an OIDC login
	// that proves a higher assurance level.
	all = append(all, oidc.StepUp(restActionContext(), o.RestConfig, oidc.StepUpOptions{
		KubeconfigGenerator: o.Generator,
		JwtPrivateKey:       o.PrivateKey,
		JwtKeyID:            o.KeyID,
	}))

	return all, nil
}
