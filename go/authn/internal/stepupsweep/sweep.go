// Package stepupsweep deletes expired step-up credentials.
//
// A step-up login (#49) writes <user>-clientconfig-stepup: a client
// certificate that lives about 15 minutes and is never renewed. Once it has
// expired it can't authenticate anything and its JWT is dead too, but nothing
// removed it, so expired keys and certificates stayed at rest, one per user
// who ever stepped up. The sweep removes them. It runs on the replica that
// holds the renewal Lease, like authn's other own-identity work.
//
// It is conservative:
//   - only Secrets named like a step-up credential are considered; session
//     credentials are never touched, expired or not;
//   - expiry is read from the stored certificate itself, and a Secret whose
//     certificate can't be read is left alone and logged;
//   - a Secret is deleted only once its certificate has been expired for
//     Grace, and only if it is still the object that was read (UID and
//     resourceVersion preconditions), so a step-up that rewrote it in the
//     meantime keeps its new credential.
package stepupsweep

import (
	"context"
	"time"

	"github.com/krateo-platformops/authn/internal/auditlog"
	"github.com/krateo-platformops/authn/internal/helpers/kube"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/rs/zerolog"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// DefaultInterval is how often the sweep runs.
	DefaultInterval = 5 * time.Minute
	// DefaultGrace is how long a certificate must have been expired before
	// its Secret is deleted, so clock skew between authn, the apiserver and
	// snowplow never removes a credential something could still accept.
	DefaultGrace = 5 * time.Minute
)

type Options struct {
	Client kubernetes.Interface
	// Namespaces to sweep; duplicates and empty entries are ignored.
	Namespaces []string
	Interval   time.Duration
	Grace      time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
	Log zerolog.Logger
	// Delete deletes one Secret and returns the apiserver's HTTP status (0
	// when it isn't known). Default: Client's typed delete, which doesn't
	// expose the status. Production passes RESTDelete, so each audit record
	// carries the status the apiserver answered.
	Delete func(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) (int, error)
	// Audit records each delete (AUDIT-4). Nil records nothing.
	Audit *auditlog.Controller
}

// RESTDelete deletes a Secret through rc and reports the apiserver's status.
func RESTDelete(rc rest.Interface) func(context.Context, string, string, metav1.DeleteOptions) (int, error) {
	return func(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) (int, error) {
		var code int
		res := rc.Delete().Namespace(namespace).Resource("secrets").Name(name).Body(&opts).Do(ctx)
		res.StatusCode(&code)
		return code, res.Error()
	}
}

// Result counts what a pass did, for the log line and for tests.
type Result struct {
	Scanned int // step-up Secrets seen
	Deleted int
	Skipped int // unreadable certificate, or rewritten/deleted concurrently
}

// Sweep makes one pass and deletes the expired step-up Secrets it finds.
func Sweep(ctx context.Context, o Options) (Result, error) {
	var res Result
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	grace := o.Grace
	if grace <= 0 {
		grace = DefaultGrace
	}
	del := o.Delete
	if del == nil {
		del = func(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) (int, error) {
			return 0, o.Client.CoreV1().Secrets(namespace).Delete(ctx, name, opts)
		}
	}

	seen := map[string]bool{}
	for _, ns := range o.Namespaces {
		if ns == "" || seen[ns] {
			continue
		}
		seen[ns] = true

		list, err := o.Client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return res, err
		}
		for _, sec := range list.Items {
			if !storage.IsStepUpSecretName(sec.Name) {
				continue
			}
			res.Scanned++
			log := o.Log.With().Str("namespace", ns).Str("secret", sec.Name).Logger()

			crt, err := kube.ParseCertificateBase64(string(sec.Data[storage.ClientCertLabel]))
			if err != nil {
				res.Skipped++
				log.Warn().Err(err).Msg("step-up sweep: certificate unreadable, left in place")
				continue
			}
			if now().Before(crt.NotAfter.Add(grace)) {
				continue
			}

			uid, rv := sec.UID, sec.ResourceVersion
			code, err := del(ctx, ns, sec.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv},
			})
			o.Audit.StepUpExpired(ctx, auditlog.SecretRef{Namespace: ns, Name: sec.Name, UID: string(uid), ResourceVersion: rv}, code, err)
			switch {
			case err == nil:
				res.Deleted++
				log.Info().Time("notAfter", crt.NotAfter).Msg("step-up sweep: expired credential deleted")
			case apierrors.IsConflict(err) || apierrors.IsNotFound(err):
				// Rewritten by a new step-up, or already gone.
				res.Skipped++
			default:
				return res, err
			}
		}
	}
	return res, nil
}

// Run sweeps at once, then every Interval, until ctx is done. A failed pass
// is logged and retried at the next tick.
func Run(ctx context.Context, o Options) {
	interval := o.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		res, err := Sweep(ctx, o)
		if err != nil {
			o.Log.Err(err).Msg("step-up sweep")
		} else if res.Deleted > 0 || res.Skipped > 0 {
			o.Log.Info().Int("scanned", res.Scanned).Int("deleted", res.Deleted).
				Int("skipped", res.Skipped).Msg("step-up sweep done")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
