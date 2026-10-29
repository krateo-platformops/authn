// Package certrenewal keeps authn's own client certificate alive.
//
// authn authenticates as a first-class cluster identity: it mints an x509
// client certificate for itself through the Kubernetes CSR API and stores it in
// the `<AUTHN_USERNAME>-clientconfig` Secret, which snowplow then presents when
// running RESTActions on authn's behalf. Nothing else ever re-issues it. A
// user's certificate is rewritten on every login, but authn's own identity used
// to be created exactly once, at startup, and then left to rot: a pod that
// outlived its certificate kept presenting an expired one, and every RESTAction
// call failed with `x509: certificate has expired or is not yet valid` until
// somebody restarted it.
//
// The gap is not theoretical, because a signer grants
// min(requested, --cluster-signing-duration, signer CA remaining life). Vanilla
// Kubernetes defaults that middle term to 8760h, so the year authn asks for
// usually survives. OpenShift pins it to 720h and rotates the CSR signer CA on
// a 30-day cycle, so the certificate comes back valid for at most 30 days — and
// for as little as a day when the rotation is imminent.
//
// The renewer closes it: it issues the certificate at startup, reads the
// granted NotAfter off the issued certificate rather than assuming the request
// held, and re-issues once the certificate passes a fraction of its REAL
// lifetime.
//
// It deliberately covers only authn's own identity. Per-user
// `<user>-clientconfig` Secrets are session-scoped: they are re-minted on every
// login, and the login JWT is now clamped to the certificate's real NotAfter
// (internal/helpers/encode), so a session can no longer outlive the credential
// it was issued with and there is nothing left for a background loop to save.
// Renewing them anyway would keep minting live cluster credentials for
// identities that may since have been deprovisioned upstream, which authn has
// no way to check. See the "Client certificate renewal" section of the README.
package certrenewal

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/krateo-platformops/authn/apis/core"
	"github.com/krateo-platformops/authn/internal/helpers/kube"
	"github.com/krateo-platformops/authn/internal/helpers/kube/config/storage"
	"github.com/krateo-platformops/authn/internal/helpers/kube/secrets"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/plumbing/kubeutil"
	"github.com/krateo-platformops/plumbing/signup"
	"github.com/rs/zerolog"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

const (
	// DefaultThreshold renews once two thirds of the granted lifetime have
	// elapsed, leaving a third of it to recover from a failing apiserver.
	DefaultThreshold = 0.66
	// DefaultDuration is the lifetime requested for authn's own certificate.
	DefaultDuration = time.Hour * 8760 // 1 year

	// minSleep floors the wait. It is a spin guard, not a schedule: a signer
	// whose CA has seconds left can only grant a window of seconds, and without
	// a floor the loop would hammer the CSR API re-issuing it.
	minSleep = time.Minute
	// retryInterval is how soon a failed read or issue is retried.
	retryInterval = time.Minute
)

type Options struct {
	RestConfig *rest.Config
	// Namespace holding the clientconfig Secret; defaults to the operator
	// namespace so reads and writes cannot drift apart.
	Namespace string
	// CAData and ServerURL are written into the stored config as-is; empty
	// CAData makes signup resolve the cluster CA itself.
	CAData    string
	ServerURL string
	Username  string
	Groups    []string
	// Duration requested from the signer. What is granted may be far less.
	Duration  time.Duration
	Threshold float64
	Log       zerolog.Logger
}

// Renewer keeps one identity's clientconfig Secret holding a valid certificate.
type Renewer struct {
	rc        *rest.Config
	namespace string
	secret    string
	caData    string
	serverURL string
	username  string
	groups    []string
	requested time.Duration
	threshold float64
	log       zerolog.Logger
}

func New(o Options) (*Renewer, error) {
	if o.RestConfig == nil {
		return nil, fmt.Errorf("a kubernetes rest config is required")
	}
	if o.Username == "" {
		return nil, fmt.Errorf("a username is required")
	}

	ns := o.Namespace
	if ns == "" {
		resolved, err := util.GetOperatorNamespace()
		if err != nil {
			return nil, fmt.Errorf("unable to resolve the namespace holding the clientconfig secret: %w", err)
		}
		ns = resolved
	}

	if o.Duration <= 0 {
		o.Duration = DefaultDuration
	}
	// A threshold outside (0,1) would renew either never or on every tick.
	if o.Threshold <= 0 || o.Threshold >= 1 {
		o.Threshold = DefaultThreshold
	}
	return &Renewer{
		rc:        o.RestConfig,
		namespace: ns,
		secret:    SecretName(o.Username),
		caData:    o.CAData,
		serverURL: o.ServerURL,
		username:  o.Username,
		groups:    o.Groups,
		requested: o.Duration,
		threshold: o.Threshold,
		log:       o.Log,
	}, nil
}

// SecretName is the clientconfig Secret an identity's credential is stored in —
// the same name the login path and plumbing's signup derive.
func SecretName(username string) string {
	return fmt.Sprintf("%s-clientconfig", kubeutil.MakeDNS1123Compatible(username))
}

// SecretName is the clientconfig Secret this renewer keeps current.
func (r *Renewer) SecretName() string { return r.secret }

// RenewAt is the instant a certificate falls due for renewal: the point at
// which threshold of its GRANTED lifetime has elapsed.
//
// Scaling with the granted lifetime, rather than applying a fixed
// remaining-time floor, is what lets one setting serve both a year-long
// certificate (renewed after ~8 months) and one a rotating signer CA cut to an
// hour (renewed after ~40 minutes).
func RenewAt(notBefore, notAfter time.Time, threshold float64) time.Time {
	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		return notAfter
	}

	return notBefore.Add(time.Duration(float64(lifetime) * threshold))
}

// Run sleeps out wait, then keeps the certificate current until ctx is
// cancelled.
//
// wait comes from the caller's own first Ensure, so the certificate is read
// exactly once per issuance: the granted NotAfter is returned by the signing
// call itself and the signer clamps it deterministically, so there is nothing
// to re-read until renewal actually falls due. A year-long certificate is one
// year-long sleep.
func (r *Renewer) Run(ctx context.Context, wait time.Duration) {
	r.log.Info().
		Str("secret", r.secret).
		Str("namespace", r.namespace).
		Dur("requested", r.requested).
		Float64("threshold", r.threshold).
		Dur("nextCheck", wait).
		Msg("client certificate renewer started")

	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			r.log.Info().Str("secret", r.secret).Msg("client certificate renewer stopped")
			return
		case <-timer.C:
		}

		var err error
		wait, err = r.Ensure(ctx)
		if err != nil {
			r.log.Err(err).Str("secret", r.secret).Msg("keeping the authn client certificate current")
		}
	}
}

// Ensure issues the certificate when it is missing, unreadable or past its
// renewal point, and reports how long to wait before checking again.
func (r *Renewer) Ensure(ctx context.Context) (time.Duration, error) {
	crt, sec, err := r.current(ctx)
	if err != nil {
		// A failed read is not evidence the credential is gone: retry the read
		// rather than churning a fresh CSR on every apiserver hiccup.
		return retryInterval, fmt.Errorf("reading the stored certificate from %q: %w", r.secret, err)
	}

	if crt == nil {
		return r.issue(ctx, "no usable certificate stored")
	}

	due := RenewAt(crt.NotBefore, crt.NotAfter, r.threshold)
	if wait := time.Until(due); wait > 0 {
		// The annotations are written when a certificate is issued, so one
		// minted by an authn that predates them — or one whose metadata write
		// was lost — carries none. Backfill here instead of leaving the granted
		// window invisible until the next renewal, which can be months away.
		r.syncAnnotations(ctx, sec)
		r.log.Debug().
			Str("secret", r.secret).
			Time("notAfter", crt.NotAfter).
			Time("renewAt", due).
			Msg("client certificate is current")
		return sleepFor(wait), nil
	}

	return r.issue(ctx, "certificate passed its renewal point")
}

// issue mints a fresh certificate and rewrites the Secret.
func (r *Renewer) issue(ctx context.Context, reason string) (time.Duration, error) {
	r.log.Info().
		Str("secret", r.secret).
		Str("reason", reason).
		Dur("requested", r.requested).
		Msg("issuing authn client certificate")

	ep, err := signup.Do(ctx, signup.Options{
		RestConfig:   r.rc,
		Namespace:    r.namespace,
		CAData:       r.caData,
		ServerURL:    r.serverURL,
		CertDuration: r.requested,
		Username:     r.username,
		UserGroups:   r.groups,
	})
	if err != nil {
		return retryInterval, fmt.Errorf("issuing a client certificate for %q: %w", r.username, err)
	}

	r.annotate(ctx)

	crt, err := kube.ParseCertificateBase64(ep.ClientCertificateData)
	if err != nil {
		// The credential is stored and usable; only its expiry is unknown, so
		// schedule the next check off the duration that was requested.
		r.log.Err(err).Str("secret", r.secret).Msg("parsing the issued certificate")
		return sleepFor(time.Duration(float64(r.requested) * r.threshold)), nil
	}

	granted := kube.Lifetime(crt)
	due := RenewAt(crt.NotBefore, crt.NotAfter, r.threshold)

	// A capped signer is otherwise invisible: the request succeeds, only
	// shorter. Say so, so the cause is in the log before anything expires.
	evt := r.log.Info()
	if kube.MateriallyShorter(granted, r.requested) {
		evt = r.log.Warn()
	}
	evt.
		Str("secret", r.secret).
		Dur("requested", r.requested).
		Dur("granted", granted).
		Time("notAfter", crt.NotAfter).
		Time("renewAt", due).
		Msg("authn client certificate issued")

	return sleepFor(time.Until(due)), nil
}

// current reads the stored certificate, returning it with the Secret that holds
// it so a caller can reconcile the Secret's metadata without reading twice. A
// missing Secret, a missing key and an unreadable certificate are all reported
// as "nothing usable stored" (nil certificate) — they call for the same response.
func (r *Renewer) current(ctx context.Context) (*x509.Certificate, *corev1.Secret, error) {
	sec, err := secrets.Get(ctx, r.rc, &core.SecretKeySelector{
		Namespace: r.namespace,
		Name:      r.secret,
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	data, ok := sec.Data[storage.ClientCertLabel]
	if !ok || len(data) == 0 {
		return nil, nil, nil
	}

	crt, err := kube.ParseCertificateBase64(string(data))
	if err != nil {
		r.log.Warn().Err(err).Str("secret", r.secret).Msg("stored certificate is unreadable")
		return nil, nil, nil
	}

	return crt, sec, nil
}

// annotate records the GRANTED validity window on the Secret it was just
// written to. signup writes the Secret with a full PUT that carries no metadata,
// so the annotations have to be re-applied after every issue.
func (r *Renewer) annotate(ctx context.Context) {
	sec, err := secrets.Get(ctx, r.rc, &core.SecretKeySelector{
		Namespace: r.namespace,
		Name:      r.secret,
	})
	if err != nil {
		r.log.Err(err).Str("secret", r.secret).Msg("reading back the stored credential to annotate it")
		return
	}

	r.syncAnnotations(ctx, sec)
}

// syncAnnotations brings sec's validity annotations in line with the certificate
// it carries, writing only when they actually differ — so the steady state costs
// no API call at all.
//
// It is a read-modify-write rather than a patch so that it needs only the `get`
// and `update` authn already holds, keeping the annotations from costing a
// `patch` verb in every deployment's RBAC. sec comes from a read and so carries
// its resourceVersion, making the write conditional on it: a concurrent writer
// loses to a conflict rather than being silently clobbered.
//
// Nothing here is worth failing a renewal over — the annotations are
// observability, not part of the credential — so every error is logged and
// swallowed.
func (r *Renewer) syncAnnotations(ctx context.Context, sec *corev1.Secret) {
	if sec == nil {
		return
	}

	want := storage.CertValidityAnnotations(string(sec.Data[storage.ClientCertLabel]))
	if len(want) == 0 {
		return
	}

	have := sec.GetAnnotations()
	stale := false
	for k, v := range want {
		if have[k] != v {
			stale = true
			break
		}
	}
	if !stale {
		return
	}

	merged := map[string]string{}
	for k, v := range have {
		merged[k] = v
	}
	for k, v := range want {
		merged[k] = v
	}
	sec.SetAnnotations(merged)

	if err := secrets.Update(ctx, r.rc, sec); err != nil {
		r.log.Err(err).Str("secret", r.secret).Msg("recording the certificate validity window")
	}
}

// sleepFor is the wait until the next check: the time left until renewal falls
// due, floored by the minSleep spin guard.
func sleepFor(d time.Duration) time.Duration {
	if d < minSleep {
		return minSleep
	}

	return d
}
