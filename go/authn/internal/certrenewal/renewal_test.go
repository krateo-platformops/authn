package certrenewal

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

func TestRenewAt(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		lifetime  time.Duration
		threshold float64
		want      time.Duration // elapsed since notBefore
	}{
		{
			// The year authn asks for, granted in full: renewed with four
			// months to spare.
			name:      "one year at two thirds",
			lifetime:  time.Hour * 8760,
			threshold: 0.66,
			want:      time.Duration(float64(time.Hour*8760) * 0.66),
		},
		{
			// OpenShift's cap. The same threshold now renews after ~20 days
			// instead of ~8 months, with no reconfiguration.
			name:      "openshift 720h cap",
			lifetime:  time.Hour * 720,
			threshold: 0.66,
			want:      time.Duration(float64(time.Hour*720) * 0.66),
		},
		{
			// Signer CA about to rotate: the whole window is an hour, and the
			// renewal point scales down with it.
			name:      "one hour granted",
			lifetime:  time.Hour,
			threshold: 0.66,
			want:      time.Minute*39 + time.Second*36,
		},
		{
			name:      "half of a day",
			lifetime:  time.Hour * 24,
			threshold: 0.5,
			want:      time.Hour * 12,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RenewAt(notBefore, notBefore.Add(tc.lifetime), tc.threshold)
			assert.Equal(t, notBefore.Add(tc.want), got)
			assert.True(t, got.Before(notBefore.Add(tc.lifetime)),
				"renewal must fall before expiry")
		})
	}
}

// An already-expired or zero-length window has no renewal point to compute;
// RenewAt must still return something in the past so the caller re-issues
// rather than dividing its way into a future date.
func TestRenewAtDegenerateWindow(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	assert.Equal(t, at, RenewAt(at, at, 0.66))
	assert.Equal(t, at, RenewAt(at.Add(time.Hour), at, 0.66))
}

func TestNewNormalizesOptions(t *testing.T) {
	tests := []struct {
		name          string
		opts          Options
		wantDuration  time.Duration
		wantThreshold float64
	}{
		{
			name:          "zero values fall back to the defaults",
			opts:          Options{},
			wantDuration:  DefaultDuration,
			wantThreshold: DefaultThreshold,
		},
		{
			// A threshold of 1 would renew only at expiry, 0 immediately and a
			// negative one before the certificate exists.
			name:          "out of range threshold falls back",
			opts:          Options{Threshold: 1},
			wantDuration:  DefaultDuration,
			wantThreshold: DefaultThreshold,
		},
		{
			name:          "negative threshold falls back",
			opts:          Options{Threshold: -0.5},
			wantDuration:  DefaultDuration,
			wantThreshold: DefaultThreshold,
		},
		{
			name:          "explicit values are kept",
			opts:          Options{Duration: time.Hour * 720, Threshold: 0.5},
			wantDuration:  time.Hour * 720,
			wantThreshold: 0.5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.RestConfig = &rest.Config{}
			tc.opts.Username = "authn"
			tc.opts.Namespace = "krateo-system"
			tc.opts.Log = zerolog.Nop()

			r, err := New(tc.opts)
			require.NoError(t, err)

			assert.Equal(t, tc.wantDuration, r.requested)
			assert.Equal(t, tc.wantThreshold, r.threshold)
		})
	}
}

func TestNewRequiresIdentity(t *testing.T) {
	_, err := New(Options{Username: "authn", Namespace: "krateo-system"})
	assert.Error(t, err, "a nil rest config must be rejected")

	_, err = New(Options{RestConfig: &rest.Config{}, Namespace: "krateo-system"})
	assert.Error(t, err, "an empty username must be rejected")
}

func TestSecretName(t *testing.T) {
	assert.Equal(t, "authn-clientconfig", SecretName("authn"))
	// The name has to survive being used as a DNS-1123 object name, the same
	// way plumbing's signup derives it.
	assert.Equal(t, "pinocpalloemailcom-clientconfig", SecretName("pinoc.pallo@email.com"))
}

// The wait is the real time until renewal, however long: a year-long
// certificate parks the loop for months rather than being re-checked. Only the
// spin guard clips it, and only under a minute.
func TestSleepFor(t *testing.T) {
	eightMonths := time.Duration(float64(time.Hour*8760) * DefaultThreshold)

	assert.Equal(t, eightMonths, sleepFor(eightMonths), "a multi-month wait is slept on in full")
	assert.Equal(t, time.Minute*30, sleepFor(time.Minute*30), "so is a short one")
	assert.Equal(t, minSleep, sleepFor(time.Second), "sub-minute waits hit the spin guard")
	assert.Equal(t, minSleep, sleepFor(-time.Hour), "a past due date is floored, not negative")
}
