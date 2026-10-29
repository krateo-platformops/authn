// Package leader runs work on exactly one authn replica at a time, elected
// through a coordination.k8s.io Lease.
//
// authn's own-identity work, issuing and renewing authn-clientconfig and the
// identity-annotation backfill, must have a single writer: the CSR is named
// after the username, and an existing CSR is deleted and recreated, so two
// replicas renewing at once would delete each other's in-flight requests.
// Electing a leader for that work lets every replica serve logins while only one
// writes, so authn can run with more than one replica.
package leader

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// CertRenewalLease is the Lease that elects the replica doing authn's
// own-identity work.
const CertRenewalLease = "authn-cert-renewal"

// Default lease timings, the conventional controller values: a crashed
// leader is replaced within LeaseDuration; a graceful shutdown releases the
// lease at once.
const (
	DefaultLeaseDuration = 15 * time.Second
	DefaultRenewDeadline = 10 * time.Second
	DefaultRetryPeriod   = 2 * time.Second
)

type Options struct {
	Client    kubernetes.Interface
	Namespace string
	// Name of the Lease.
	Name string
	// Identity of this replica; must be unique among the candidates.
	Identity string

	// Zero values fall back to the Default* timings.
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration

	Log zerolog.Logger
}

// Run campaigns for the Lease until ctx is done. Each time this replica
// becomes leader, lead runs with a context that is cancelled the moment
// leadership is lost; lead must return promptly once its context is done.
// After losing leadership Run campaigns again, so a replica that lost the
// lease during an apiserver hiccup rejoins as a candidate.
func Run(ctx context.Context, o Options, lead func(ctx context.Context)) error {
	if o.Client == nil || o.Namespace == "" || o.Name == "" || o.Identity == "" {
		return fmt.Errorf("leader election: client, namespace, name and identity are required")
	}

	cfg := leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Namespace: o.Namespace, Name: o.Name},
			Client:     o.Client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: o.Identity},
		},
		LeaseDuration:   orDefault(o.LeaseDuration, DefaultLeaseDuration),
		RenewDeadline:   orDefault(o.RenewDeadline, DefaultRenewDeadline),
		RetryPeriod:     orDefault(o.RetryPeriod, DefaultRetryPeriod),
		ReleaseOnCancel: true,
		Name:            o.Name,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(lctx context.Context) {
				o.Log.Info().Str("lease", o.Name).Str("identity", o.Identity).Msg("acquired leadership")
				lead(lctx)
			},
			OnStoppedLeading: func() {
				o.Log.Info().Str("lease", o.Name).Str("identity", o.Identity).Msg("leadership released")
			},
			OnNewLeader: func(identity string) {
				if identity != o.Identity {
					o.Log.Info().Str("lease", o.Name).Str("leader", identity).Msg("standing by")
				}
			},
		},
	}

	elector, err := leaderelection.NewLeaderElector(cfg)
	if err != nil {
		return fmt.Errorf("leader election: %w", err)
	}

	// Run returns when leadership is lost or ctx is done; campaign again
	// unless we are shutting down.
	for ctx.Err() == nil {
		elector.Run(ctx)
	}
	return nil
}

func orDefault(v, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return v
}
