package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// internalTLSConfig is the internal listener's TLS (authn#145): served from
// certFile and keyFile, which the chart mounts from the cert-manager Secret of
// the <release>-internal Certificate. With neither set it is nil, and the
// internal listener stays plain HTTP, as before. With only one set it is an
// error: a half-configured TLS listener must not quietly fall back to plain
// HTTP. A certificate that can't be loaded at startup is an error too, so
// authn never starts serving the internal port without the TLS it was told
// to serve.
func internalTLSConfig(certFile, keyFile string, log zerolog.Logger) (*tls.Config, error) {
	switch {
	case certFile == "" && keyFile == "":
		return nil, nil
	case certFile == "" || keyFile == "":
		return nil, errors.New("the internal listener's TLS needs both a certificate and a key file")
	}
	r, err := newCertReloader(certFile, keyFile, log)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.GetCertificate}, nil
}

// certReloader serves a certificate from files that a Secret volume mounts.
// cert-manager renews the Secret before the certificate expires, and the
// kubelet swaps the mounted files. The reloader notices on the next handshake
// (the files' modification time or size changed) and loads the new pair, so a
// rotation needs no restart. A pair that doesn't load, say read while the
// kubelet is mid-swap, keeps the last good certificate in service and is tried
// again on the next handshake.
type certReloader struct {
	certFile, keyFile string
	log               zerolog.Logger

	mu        sync.Mutex
	cert      *tls.Certificate
	certStamp fileStamp
	keyStamp  fileStamp
}

// fileStamp is what tells a rewritten file from the one already loaded.
type fileStamp struct {
	mod  time.Time
	size int64
}

func stampOf(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{mod: fi.ModTime(), size: fi.Size()}, nil
}

func newCertReloader(certFile, keyFile string, log zerolog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	if err := r.load(); err != nil {
		return nil, fmt.Errorf("loading the internal listener's certificate: %w", err)
	}
	return r, nil
}

// load reads the pair and makes it the one served. Callers hold r.mu, or own
// r exclusively.
func (r *certReloader) load() error {
	cs, err := stampOf(r.certFile)
	if err != nil {
		return err
	}
	ks, err := stampOf(r.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.certStamp, r.keyStamp = &cert, cs, ks
	return nil
}

// GetCertificate is tls.Config.GetCertificate: the current pair, reloaded
// first if either file changed since it was loaded.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cs, cerr := stampOf(r.certFile)
	ks, kerr := stampOf(r.keyFile)
	if cerr == nil && kerr == nil && (cs != r.certStamp || ks != r.keyStamp) {
		if err := r.load(); err != nil {
			r.log.Warn().Err(err).Msg("the internal listener's rotated certificate didn't load; serving the previous one")
		} else {
			r.log.Info().Msg("the internal listener's certificate was rotated")
		}
	}
	return r.cert, nil
}

// listenAndServe runs s on its address: over TLS when it has a TLSConfig (the
// internal listener with authn#145's certificate), plain HTTP otherwise.
func listenAndServe(s *http.Server) error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return serveOn(s, l)
}

// serveOn is listenAndServe on a listener already open, which the tests use.
func serveOn(s *http.Server, l net.Listener) error {
	if s.TLSConfig != nil {
		return s.ServeTLS(l, "", "")
	}
	return s.Serve(l)
}
