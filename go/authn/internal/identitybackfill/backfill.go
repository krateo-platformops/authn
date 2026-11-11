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
//
// It also gives an existing service identity's Secret the owner a login now
// sets: its ServiceAccount mapping, by UID, so the garbage collector deletes the
// credential once the mapping is retired. That applies only to Secrets in the
// mappings' namespace (an ownerReference can't cross namespaces), and only to
// those with no owner yet, so a Secret issued under an earlier mapping of the
// same name is never re-attached to a newer one. A service Secret whose mapping
// is gone is reported as an orphan and left in place: deleting a credential is
// an operator's decision, never this pass's.
package identitybackfill

import (
	"context"
	"fmt"
	"github.com/krateo-platformops/authn/internal/auditlog"
	"strings"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/resolvers"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/plumbing/endpoints"
	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// Lookup answers whether an identity with a given username exists for the
// strategies whose identities are declared as Kubernetes objects.
type Lookup interface {
	// ServiceAccountMapping returns the mapping named username, or nil when
	// there is none.
	ServiceAccountMapping(ctx context.Context, username string) (*sav1alpha1.ServiceAccount, error)
	BasicUserExists(ctx context.Context, username string) (bool, error)
}

type Options struct {
	RestConfig *rest.Config
	// Namespaces to scan; duplicates and empty entries are ignored.
	Namespaces []string
	// SelfUsername is authn's own identity (AUTHN_USERNAME).
	SelfUsername string
	// MappingNamespace holds the ServiceAccount mappings (the operator
	// namespace). Only Secrets there are given a mapping owner.
	MappingNamespace string
	// Lookup defaults to the cluster resolvers.
	Lookup Lookup
	Log    zerolog.Logger
	// Audit records each write: every one stamps an authorization-bearing
	// annotation or an owner (AUDIT-4). Nil records nothing.
	Audit *auditlog.Controller
}

// Result counts what a run did, for the log line and for tests.
type Result struct {
	Scanned int
	Stamped int
	Skipped int
	// Owned counts service Secrets given their mapping as owner.
	Owned int
	// Orphaned counts service Secrets whose mapping is gone, left in place.
	Orphaned int
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
			if !strings.HasSuffix(sec.Name, endpoints.ClientConfigSuffix) {
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

			merged := map[string]string{}
			for k, v := range sec.GetAnnotations() {
				merged[k] = v
			}
			for k, v := range missing {
				merged[k] = v
			}

			owner, orphan, err := missingOwner(ctx, sec, merged, o.MappingNamespace, lookup)
			if err != nil {
				o.Log.Warn().Err(err).Str("secret", sec.Name).Str("namespace", ns).
					Msg("clientconfig owner not backfilled")
			}
			if orphan {
				res.Orphaned++
				o.Log.Warn().Str("secret", sec.Name).Str("namespace", ns).
					Str("notAfter", merged[storage.NotAfterAnnotation]).
					Msg("service clientconfig has no ServiceAccount mapping; left in place")
			}

			if len(missing) == 0 && owner == nil {
				continue
			}
			sec.SetAnnotations(merged)
			if owner != nil {
				sec.SetOwnerReferences([]metav1.OwnerReference{*owner})
			}

			// sec carries the resourceVersion from the list, so a concurrent
			// writer (a login rewriting the Secret) wins with a conflict
			// instead of being clobbered.
			ref := auditlog.SecretRef{Namespace: sec.Namespace, Name: sec.Name}
			code, err := secrets.Update(ctx, o.RestConfig, sec)
			if err == nil {
				ref.UID, ref.ResourceVersion = string(sec.UID), sec.ResourceVersion
			}
			o.Audit.IdentityWritten(ctx, auditlog.ActionIdentityBackfilled, ref, code, err)
			if err != nil {
				res.Skipped++
				o.Log.Warn().Err(err).Str("secret", sec.Name).Str("namespace", ns).
					Msg("identity annotations not backfilled")
				continue
			}
			if len(missing) > 0 {
				res.Stamped++
				o.Log.Info().Str("secret", sec.Name).Str("namespace", ns).
					Str("strategy", merged[storage.StrategyAnnotation]).
					Msg("identity annotations backfilled")
			}
			if owner != nil {
				res.Owned++
				o.Log.Info().Str("secret", sec.Name).Str("namespace", ns).
					Str("mapping", owner.Name).Msg("clientconfig owner backfilled")
			}
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

// missingOwner returns the ownerReference a service identity's Secret lacks: its
// ServiceAccount mapping, by UID. It returns nil for a Secret outside the
// mappings' namespace, one that isn't a service identity's, or one that already
// has an owner; and orphan=true when the mapping is gone.
func missingOwner(ctx context.Context, sec *corev1.Secret, annotations map[string]string, mappingNS string, lookup Lookup) (_ *metav1.OwnerReference, orphan bool, _ error) {
	if mappingNS == "" || sec.Namespace != mappingNS {
		return nil, false, nil
	}
	if storage.Strategy(annotations[storage.StrategyAnnotation]) != storage.StrategyServiceAccount {
		return nil, false, nil
	}
	if len(sec.GetOwnerReferences()) > 0 {
		return nil, false, nil
	}

	crt, err := kube.ParseCertificateBase64(string(sec.Data[storage.ClientCertLabel]))
	if err != nil {
		return nil, false, fmt.Errorf("reading the stored certificate: %w", err)
	}
	mapping, err := lookup.ServiceAccountMapping(ctx, crt.Subject.CommonName)
	if err != nil {
		return nil, false, fmt.Errorf("looking up a ServiceAccount mapping for %q: %w", crt.Subject.CommonName, err)
	}
	if mapping == nil {
		return nil, true, nil
	}
	ref := mapping.OwnerReference()
	return &ref, false, nil
}

// strategyOf proves which strategy issued username's credential, or reports
// StrategyUnknown when it cannot.
func strategyOf(ctx context.Context, username, self string, lookup Lookup) (storage.Strategy, error) {
	if username == self {
		return storage.StrategySelf, nil
	}

	mapping, err := lookup.ServiceAccountMapping(ctx, username)
	sa := mapping != nil
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

func (c clusterLookup) ServiceAccountMapping(_ context.Context, username string) (*sav1alpha1.ServiceAccount, error) {
	mapping, err := resolvers.ServiceAccountMappingGet(c.rc, username)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapping, nil
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
