// Package serviceaccount implements the Kubernetes intra-service auth login strategy: a
// backend service presents its own (audience-bound) ServiceAccount token, authn validates
// it via the Kubernetes TokenReview API, maps the authenticated ServiceAccount to a
// serviceaccount.authn.krateo.io/ServiceAccount mapping (the allowlist), and issues the same
// JWT + clientconfig the other strategies do. See docs/design/kubernetes-intra-service-auth.md.
package serviceaccount

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/encode"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/shortid"
	"github.com/rs/zerolog"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	Path = "/serviceaccount/login"
	// DefaultAudience the projected SA token must be bound to.
	DefaultAudience = "authn"
)

type LoginOptions struct {
	KubeconfigGenerator kubeconfig.Generator
	JwtDuration         time.Duration
	JwtSingKey          string
	// Audience the projected SA token must carry (enforced via TokenReview); defaults to
	// DefaultAudience. Binding the audience prevents replay of tokens minted for the
	// apiserver or another service.
	Audience string
}

func Login(rc *rest.Config, opts LoginOptions) routes.Route {
	aud := opts.Audience
	if aud == "" {
		aud = DefaultAudience
	}
	return &loginRoute{
		rc:          rc,
		gen:         opts.KubeconfigGenerator,
		jwtDuration: opts.JwtDuration,
		jwtSignKey:  opts.JwtSingKey,
		audience:    aud,
	}
}

var _ routes.Route = (*loginRoute)(nil)

type loginRoute struct {
	rc          *rest.Config
	gen         kubeconfig.Generator
	jwtDuration time.Duration
	jwtSignKey  string
	audience    string
}

func (r *loginRoute) Name() string    { return "serviceaccount" }
func (r *loginRoute) Pattern() string { return Path }
func (r *loginRoute) Method() string  { return http.MethodPost }

func (r *loginRoute) Handler() http.HandlerFunc {
	return func(wri http.ResponseWriter, req *http.Request) {
		log := zerolog.Ctx(req.Context())

		token, ok := bearerToken(req)
		if !ok {
			wri.Header().Set("WWW-Authenticate", `Bearer realm="krateo"`)
			http.Error(wri, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := r.validate(req.Context(), token)
		if err != nil {
			log.Err(err).Msg("serviceaccount auth failed")
			encode.Forbidden(wri, err)
			return
		}
		log.Debug().
			Str("username", user.GetUserName()).
			Str("groups", strings.Join(user.GetGroups(), ",")).
			Msg("serviceaccount auth succeeded")

		dat, err := r.gen.Generate(user)
		if err != nil {
			log.Err(err).Msg("kubeconfig creation failure")
			encode.InternalError(wri, err)
			return
		}

		encode.Success(wri, dat, &encode.Extras{
			UserInfo:    user,
			JwtDuration: r.jwtDuration,
			JwtSingKey:  r.jwtSignKey,
		})
	}
}

// validate verifies the SA token via the Kubernetes TokenReview API (audience-bound), maps
// the authenticated ServiceAccount to a ServiceAccount mapping (the allowlist), and builds
// the issued identity (username = mapping name, groups = mapping spec.groups).
func (r *loginRoute) validate(ctx context.Context, token string) (userinfo.Info, error) {
	clientset, err := kubernetes.NewForConfig(r.rc)
	if err != nil {
		return nil, err
	}

	tr := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{r.audience},
		},
	}
	tr, err = clientset.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review: %w", err)
	}
	if tr.Status.Error != "" {
		return nil, fmt.Errorf("token review: %s", tr.Status.Error)
	}
	if !tr.Status.Authenticated {
		return nil, fmt.Errorf("token not authenticated")
	}
	if !containsAudience(tr.Status.Audiences, r.audience) {
		return nil, fmt.Errorf("token audience mismatch (require %q)", r.audience)
	}

	saNamespace, saName, err := parseServiceAccountUsername(tr.Status.User.Username)
	if err != nil {
		return nil, err
	}

	mapping, err := resolvers.ServiceAccountForSA(r.rc, saNamespace, saName)
	if err != nil {
		return nil, err
	}

	exts := userinfo.Extensions{}
	exts.Add("name", mapping.Spec.DisplayName)

	uid, _ := shortid.Generate()
	return userinfo.NewDefaultUser(mapping.Name, uid, mapping.Spec.Groups, exts), nil
}

func bearerToken(req *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := req.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

func containsAudience(auds []string, want string) bool {
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}

// parseServiceAccountUsername parses a TokenReview username of the form
// "system:serviceaccount:<namespace>:<name>".
func parseServiceAccountUsername(u string) (namespace, name string, err error) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(u, prefix) {
		return "", "", fmt.Errorf("not a service account token (username %q)", u)
	}
	parts := strings.SplitN(strings.TrimPrefix(u, prefix), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("malformed service account username %q", u)
	}
	return parts[0], parts[1], nil
}
