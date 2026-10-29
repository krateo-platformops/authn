// Package identitybackfill stamps the identity annotations
// (storage.StrategyAnnotation, storage.GroupsAnnotation) onto
// <username>-clientconfig Secrets written before authn recorded them.
//
// Every Secret authn writes from now on carries them. Identities that do not
// log in again would otherwise stay unannotated indefinitely, and policy that
// decides from the annotations (tenant onboarding) could not tell them apart.
// So, once at startup, authn fills in what it can prove:
//
//   - groups: read from the stored certificate's O=, exactly what it grants;
//   - strategy: "self" for authn's own identity, "serviceaccount" when a
//     ServiceAccount mapping with that username exists, "basic" when a basic
//     User with that username exists, and "unknown" otherwise (including when
//     both exist). Policy is expected to fail closed on "unknown".
//
// Existing annotations are never overwritten: whatever a login wrote is newer
// and better informed than anything derived here.
package identitybackfill

import (
	"context"
	"fmt"
	"strings"

	"github.com/krateo-platformops/authn/internal/helpers/kube"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

const clientConfigSuffix = "-clientconfig"

// Lookup answers whether an identity with a given username exists for the
// strategies whose identities are declared as Kubernetes objects.
type Lookup interface {
	ServiceAccountMappingExists(ctx context.Context, username string) (bool, error)
	BasicUserExists(ctx context.Context, username string) (bool, error)
}

type Options struct {
	RestConfig *rest.Config
	// Namespaces to scan; duplicates and empty entries are ignored.
	Namespaces []string
	// SelfUsername is authn's own identity (AUTHN_USERNAME).
	SelfUsername string
	// Lookup defaults to the cluster resolvers.
	Lookup Lookup
	Log    zerolog.Logger
}

// Result counts what a run did, for the log line and for tests.
type Result struct {
	Scanned int
	Stamped int
	Skipped int
}

// Run scans the clientconfig Secrets and stamps missing identity annotations.
// A Secret that cannot be stamped safely (unreadable certificate, a lookup
// error) is skipped and logged, never stamped with a guess; the next start
// retries it.
func Run(ctx context.Context, o Options) (Result, error) {
	var res Result

	lookup := o.Lookup
	if lookup == nil {
		lookup = clusterLookup{rc: o.RestConfig}
	}

	seen := map[string]bool{}
	for _, ns := range o.Namespaces {
		if ns == "" || seen[ns] {
			continue
		}
		seen[ns] = true

		list, err := secrets.List(ctx, o.RestConfig, ns)
		if err != nil {
			return res, fmt.Errorf("listing secrets in %s: %w", ns, err)
		}

		for i := range list.Items {
			sec := &list.Items[i]
			if !strings.HasSuffix(sec.Name, clientConfigSuffix) {
				continue
			}
			res.Scanned++

			missing, err := missingAnnotations(ctx, sec, o.SelfUsername, lookup)
			if err != nil {
				res.Skipped++
				o.Log.Warn().Err(err).Str("secret", sec.Name).Str("namespace", ns).
					Msg("identity annotations not backfilled")
				continue
			}
			if len(missing) == 0 {
				continue
			}

			merged := map[string]string{}
			for k, v := range sec.GetAnnotations() {
				merged[k] = v
			}
			for k, v := range missing {
				merged[k] = v
			}
			sec.SetAnnotations(merged)

			// sec carries the resourceVersion from the list, so a concurrent
			// writer (a login rewriting the Secret) wins with a conflict
			// instead of being clobbered.
			if err := secrets.Update(ctx, o.RestConfig, sec); err != nil {
				res.Skipped++
				o.Log.Warn().Err(err).Str("secret", sec.Name).Str("namespace", ns).
					Msg("identity annotations not backfilled")
				continue
			}
			res.Stamped++
			o.Log.Info().Str("secret", sec.Name).Str("namespace", ns).
				Str("strategy", merged[storage.StrategyAnnotation]).
				Msg("identity annotations backfilled")
		}
	}

	return res, nil
}

// missingAnnotations returns the identity annotations sec lacks, derived from
// its certificate. It returns nothing when both are already present.
func missingAnnotations(ctx context.Context, sec *corev1.Secret, self string, lookup Lookup) (map[string]string, error) {
	have := sec.GetAnnotations()
	_, hasStrategy := have[storage.StrategyAnnotation]
	_, hasGroups := have[storage.GroupsAnnotation]
	if hasStrategy && hasGroups {
		return nil, nil
	}

	cert := string(sec.Data[storage.ClientCertLabel])
	crt, err := kube.ParseCertificateBase64(cert)
	if err != nil {
		return nil, fmt.Errorf("reading the stored certificate: %w", err)
	}

	strategy, err := strategyOf(ctx, crt.Subject.CommonName, self, lookup)
	if err != nil {
		return nil, err
	}

	want, err := storage.IdentityAnnotations(strategy, cert)
	if err != nil {
		return nil, err
	}

	missing := map[string]string{}
	for k, v := range want {
		if _, ok := have[k]; !ok {
			missing[k] = v
		}
	}
	return missing, nil
}

// strategyOf proves which strategy issued username's credential, or reports
// StrategyUnknown when it cannot.
func strategyOf(ctx context.Context, username, self string, lookup Lookup) (storage.Strategy, error) {
	if username == self {
		return storage.StrategySelf, nil
	}

	sa, err := lookup.ServiceAccountMappingExists(ctx, username)
	if err != nil {
		return "", fmt.Errorf("looking up a ServiceAccount mapping for %q: %w", username, err)
	}
	basic, err := lookup.BasicUserExists(ctx, username)
	if err != nil {
		return "", fmt.Errorf("looking up a basic User for %q: %w", username, err)
	}

	switch {
	case sa && !basic:
		return storage.StrategyServiceAccount, nil
	case basic && !sa:
		return storage.StrategyBasic, nil
	default:
		// Neither (ldap/oauth/oidc leave no object behind) or both (ambiguous).
		return storage.StrategyUnknown, nil
	}
}

type clusterLookup struct{ rc *rest.Config }

func (c clusterLookup) ServiceAccountMappingExists(_ context.Context, username string) (bool, error) {
	_, err := resolvers.ServiceAccountMappingGet(c.rc, username)
	return exists(err)
}

func (c clusterLookup) BasicUserExists(_ context.Context, username string) (bool, error) {
	_, err := resolvers.UserGet(c.rc, username)
	return exists(err)
}

func exists(err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}
