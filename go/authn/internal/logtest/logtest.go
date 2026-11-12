// Package logtest checks that authn's log lines carry no identity.
//
// A test signs in with sentinel identities (User, Subject, Email, or anything
// else that contains Marker), captures every log line at debug level with
// Capture, and fails with NoIdentity if a sentinel reached a line. Identity
// lives only in the audit record (internal/auditlog), joined to the log lines
// by session.id.
package logtest

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

// Marker is in every sentinel. A log line that contains it carries an
// identity, or something derived from one (a Secret named after the user, a
// DN, a claim).
const Marker = "zz-sentinel"

// Sentinel identities.
const (
	User    = Marker + "-user"
	Subject = Marker + "-sub"
	Email   = Marker + "@example.test"
)

// Buffer collects log lines. It is safe for concurrent writes.
type Buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Capture returns a buffer and a debug-level logger writing to it.
func Capture() (*Buffer, zerolog.Logger) {
	b := &Buffer{}
	return b, zerolog.New(b).Level(zerolog.DebugLevel)
}

// Request returns req with a capturing logger on its context, where the
// routes find theirs (zerolog.Ctx), and the buffer it writes to.
func Request(req *http.Request) (*http.Request, *Buffer) {
	b, l := Capture()
	return req.WithContext(l.WithContext(req.Context())), b
}

// NoIdentity fails t when a line in b contains Marker. It also fails when b is
// empty: a check of nothing would pass whatever the code logs. A path that
// logs nothing of its own, such as some successful logins, uses
// NoIdentityIfAny.
func NoIdentity(t testing.TB, b *Buffer) {
	t.Helper()
	if strings.TrimSpace(b.String()) == "" {
		t.Errorf("nothing was logged, so nothing was checked")
		return
	}
	NoIdentityIfAny(t, b)
}

// NoIdentityIfAny fails t when a line in b contains Marker.
func NoIdentityIfAny(t testing.TB, b *Buffer) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if strings.Contains(line, Marker) {
			t.Errorf("a log line carries an identity (%q):\n%s", Marker, line)
		}
	}
}
