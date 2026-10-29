package leader

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

// Two replicas campaign for the same Lease: exactly one leads at any time,
// and when the leader goes away the other takes over.
func TestSingleLeaderAndFailover(t *testing.T) {
	client := fake.NewSimpleClientset()

	var (
		mu      sync.Mutex
		leading = map[string]bool{}
		maxLive int32
		live    int32
		ever    = map[string]bool{}
	)

	lead := func(id string) func(context.Context) {
		return func(ctx context.Context) {
			n := atomic.AddInt32(&live, 1)
			for {
				m := atomic.LoadInt32(&maxLive)
				if n <= m || atomic.CompareAndSwapInt32(&maxLive, m, n) {
					break
				}
			}
			mu.Lock()
			leading[id], ever[id] = true, true
			mu.Unlock()

			<-ctx.Done()

			mu.Lock()
			leading[id] = false
			mu.Unlock()
			atomic.AddInt32(&live, -1)
		}
	}

	opts := func(id string) Options {
		return Options{
			Client: client, Namespace: "krateo-system", Name: "authn-cert-renewal", Identity: id,
			LeaseDuration: 600 * time.Millisecond, RenewDeadline: 400 * time.Millisecond, RetryPeriod: 100 * time.Millisecond,
			Log: zerolog.Nop(),
		}
	}

	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopA()
	defer stopB()

	doneA := make(chan struct{})
	go func() { _ = Run(ctxA, opts("a"), lead("a")); close(doneA) }()
	go func() { _ = Run(ctxB, opts("b"), lead("b")) }()

	current := func() string {
		mu.Lock()
		defer mu.Unlock()
		for id, on := range leading {
			if on {
				return id
			}
		}
		return ""
	}

	require.Eventually(t, func() bool { return current() != "" }, 5*time.Second, 20*time.Millisecond, "someone must lead")
	first := current()

	// Stop whichever replica leads; the other must take over.
	if first == "a" {
		stopA()
		<-doneA
	} else {
		stopB()
	}
	require.Eventually(t, func() bool { c := current(); return c != "" && c != first }, 5*time.Second, 20*time.Millisecond,
		"the other replica must take over")

	if first != "a" {
		stopA()
		<-doneA
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&maxLive), "never more than one leader at a time")
	assert.True(t, ever["a"] && ever["b"], "both replicas led, one after the other")
}

func TestRunValidatesOptions(t *testing.T) {
	err := Run(context.Background(), Options{}, func(context.Context) {})
	assert.Error(t, err)
}
