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
//
// With exact naming on (storage.Naming.Exact, authn#140) it also stamps the
// identity keys every Secret authn writes now carries (authn#144): the username
// annotation, the principal label and the username-label label (acmp's
// tenant-policy design, §2.5). The username is the certificate's CN, never the
// Secret's name: a legacy name is shared by usernames (john.doe and johndoe
// are both johndoe-clientconfig). A key already present is never overwritten,
// even with another value: the tenant policy may already have generated from
// it. Each such key is logged instead, by its kind, its name and the Secret's
// uid, and recorded as a declined update (auditlog.Controller.IdentityKept,
// audit's kept_existing_value), never with its value. A Secret
// whose certificate can't be read (one authn didn't write) is skipped, and
// legacy-named Secrets are stamped like any other.
package identitybackfill

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/authn/internal/auditlog"

	sav1alpha1 "github.com/krateo-platformops/authn/apis/authn/serviceaccount/v1alpha1"
	"github.com/krateo-platformops/authn/internal/helpers/kube"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/kerr"
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
	// annotation or an owner (AUDIT-4). With exact naming it also records each
	// identity key left as found, one record per key. Nil records nothing.
	Audit *auditlog.Controller
	// Naming, with Exact set, stamps the identity keys of authn#144 too
	// (storage.ExactIdentity). The zero value stamps what authn always has.
	Naming storage.Naming
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
	// Inconsistent counts Secrets holding an identity key with another value
	// than their certificate proves, left as found (exact naming only).
	Inconsistent int
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
				o.Log.Warn().Err(err).Str("secret.uid", string(sec.UID)).Str("namespace", ns).
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

			var exact exactKeys
			if o.Naming.Exact {
				exact, err = missingExact(ctx, sec, merged, lookup)
				if err != nil {
					res.Skipped++
					o.Log.Warn().Err(err).Str("secret.uid", string(sec.UID)).Str("namespace", ns).
						Msg("identity keys not backfilled")
					continue
				}
				ref := auditlog.SecretRef{Namespace: sec.Namespace, Name: sec.Name,
					UID: string(sec.UID), ResourceVersion: sec.ResourceVersion}
				for _, k := range exact.conflicts {
					// The key, never its values: they are identities.
					o.Log.Warn().Str("secret.uid", string(sec.UID)).Str("namespace", ns).
						Str("kind", k.Kind).Str("key", k.Key).
						Msg("identity key differs from the certificate; left as found")
					o.Audit.IdentityKept(ctx, ref, k.Kind, k.Key)
				}
				if len(exact.conflicts) > 0 {
					res.Inconsistent++
				}
				for k, v := range exact.annotations {
					merged[k] = v
				}
			}

			owner, orphan, err := missingOwner(ctx, sec, merged, o.MappingNamespace, lookup)
			if err != nil {
				o.Log.Warn().Err(err).Str("secret.uid", string(sec.UID)).Str("namespace", ns).
					Msg("clientconfig owner not backfilled")
			}
			if orphan {
				res.Orphaned++
				o.Log.Warn().Str("secret.uid", string(sec.UID)).Str("namespace", ns).
					Str("notAfter", merged[storage.NotAfterAnnotation]).
					Msg("service clientconfig has no ServiceAccount mapping; left in place")
			}

			if len(missing) == 0 && owner == nil && exact.empty() {
				continue
			}
			before := sec.DeepCopy()
			sec.SetAnnotations(merged)
			if len(exact.labels) > 0 {
				labels := map[string]string{}
				for k, v := range sec.GetLabels() {
					labels[k] = v
				}
				for k, v := range exact.labels {
					labels[k] = v
				}
				sec.SetLabels(labels)
			}
			if owner != nil {
				sec.SetOwnerReferences([]metav1.OwnerReference{*owner})
			}
			// Every write stamps authorization-bearing content or an owner. With
			// exact naming the content is judged by plumbing's content.DiffersWith
			// over storage.ContentKeys, labels included.
			record := owner != nil || !o.Naming.Exact || o.Naming.AuthorizationDiffers(before, sec)

			// sec carries the resourceVersion from the list, so a concurrent
			// writer (a login rewriting the Secret) wins with a conflict
			// instead of being clobbered.
			ref := auditlog.SecretRef{Namespace: sec.Namespace, Name: sec.Name}
			code, err := secrets.Update(ctx, o.RestConfig, sec)
			if err == nil {
				ref.UID, ref.ResourceVersion = string(sec.UID), sec.ResourceVersion
			}
			if record {
				o.Audit.IdentityWritten(ctx, auditlog.ActionIdentityBackfilled, ref, code, err)
			}
			if err != nil {
				res.Skipped++
				// The apiserver's error names the Secret, which names its user.
				o.Log.Warn().Err(kerr.Wrap("updating the credential Secret", err)).
					Str("secret.uid", string(sec.UID)).Str("namespace", ns).
					Msg("identity annotations not backfilled")
				continue
			}
			if len(missing) > 0 || !exact.empty() {
				res.Stamped++
			}
			if len(missing) > 0 {
				o.Log.Info().Str("secret.uid", string(sec.UID)).Str("namespace", ns).
					Str("strategy", merged[storage.StrategyAnnotation]).
					Msg("identity annotations backfilled")
			}
			if !exact.empty() {
				o.Log.Info().Str("secret.uid", string(sec.UID)).Str("namespace", ns).
					Int("keys", len(exact.annotations)+len(exact.labels)).
					Msg("identity keys backfilled")
			}
			if owner != nil {
				res.Owned++
				o.Log.Info().Str("secret.uid", string(sec.UID)).Str("namespace", ns).
					Str("mapping.uid", string(owner.UID)).Msg("clientconfig owner backfilled")
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

// exactKeys is what authn#144's backfill stamps on one Secret, and the keys it
// found holding another value.
type exactKeys struct {
	annotations, labels map[string]string
	conflicts           []identityKey
}

// identityKey is an identity key a Secret holds with another value than its
// certificate proves: its kind (audit.MetadataKindAnnotation or
// audit.MetadataKindLabel) and its name. The kind is carried, never inferred
// from the name, since a name alone doesn't say where it was found.
type identityKey struct {
	Kind, Key string
}

func (e exactKeys) empty() bool { return len(e.annotations) == 0 && len(e.labels) == 0 }

// missingExact returns the identity keys of authn#144 sec lacks
// (storage.ExactIdentity), derived from its certificate: the username is the
// CN, never the Secret's name. annotations are sec's as this pass will write
// them, so the principal follows the strategy just stamped. A key present with
// another value is reported in conflicts and never overwritten. A principal
// that can't be proven (strategy unknown, a service identity whose mapping is
// gone) is left off, and a policy selecting on it fails closed.
func missingExact(ctx context.Context, sec *corev1.Secret, annotations map[string]string, lookup Lookup) (exactKeys, error) {
	crt, err := kube.ParseCertificateBase64(string(sec.Data[storage.ClientCertLabel]))
	if err != nil {
		return exactKeys{}, fmt.Errorf("reading the stored certificate: %w", err)
	}
	username := crt.Subject.CommonName
	if username == "" {
		return exactKeys{}, fmt.Errorf("the stored certificate names no one")
	}

	strategy := storage.Strategy(annotations[storage.StrategyAnnotation])
	declared := ""
	provable := true
	if strategy == storage.StrategyServiceAccount {
		mapping, err := lookup.ServiceAccountMapping(ctx, username)
		if err != nil {
			return exactKeys{}, kerr.Wrap("looking up the certificate's ServiceAccount mapping", err)
		}
		if mapping == nil {
			provable = false
		} else {
			declared = mapping.Spec.Principal
		}
	}
	wantAnn, wantLabels := storage.ExactIdentity(strategy, declared, username)
	if !provable {
		delete(wantLabels, storage.PrincipalLabel)
	}

	out := exactKeys{annotations: map[string]string{}, labels: map[string]string{}}
	compare := func(kind string, have, want, stamp map[string]string) {
		for k, v := range want {
			got, ok := have[k]
			switch {
			case !ok:
				stamp[k] = v
			case got != v:
				out.conflicts = append(out.conflicts, identityKey{Kind: kind, Key: k})
			}
		}
	}
	compare(audit.MetadataKindAnnotation, sec.GetAnnotations(), wantAnn, out.annotations)
	compare(audit.MetadataKindLabel, sec.GetLabels(), wantLabels, out.labels)
	sort.Slice(out.conflicts, func(i, j int) bool {
		a, b := out.conflicts[i], out.conflicts[j]
		return a.Kind < b.Kind || a.Kind == b.Kind && a.Key < b.Key
	})
	return out, nil
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
		return nil, false, kerr.Wrap("looking up the certificate's ServiceAccount mapping", err)
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
		return "", kerr.Wrap("looking up the certificate's ServiceAccount mapping", err)
	}
	basic, err := lookup.BasicUserExists(ctx, username)
	if err != nil {
		return "", kerr.Wrap("looking up the certificate's basic User", err)
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
