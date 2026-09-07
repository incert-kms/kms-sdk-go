package kmssdk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
)

// tlsOptions collects the WithTLS* options. They apply only to the
// SDK-managed HTTP client; a custom client from [WithHTTPClient] is never
// modified.
type tlsOptions struct {
	base       *tls.Config // clone of the WithTLSConfig argument, nil when unset
	caFile     string
	caPath     string
	certFile   string
	keyFile    string
	serverName string
	skipVerify bool
}

// configured reports whether any WithTLS* option was given.
func (o tlsOptions) configured() bool {
	return o.base != nil || o.hasTrustMaterial() || o.certFile != "" || o.keyFile != "" || o.skipVerify
}

// hasTrustMaterial reports whether options that only matter with certificate
// verification enabled (CA file, CA directory, server name) were given.
func (o tlsOptions) hasTrustMaterial() bool {
	return o.caFile != "" || o.caPath != "" || o.serverName != ""
}

// build assembles the *tls.Config: the cloned base (or an empty config with
// Go's defaults), CA material appended to a copy of its RootCAs, the client
// certificate appended to its Certificates, then the server name and the
// skip-verify flag.
func (o tlsOptions) build() (*tls.Config, error) {
	cfg := o.base
	if cfg == nil {
		cfg = &tls.Config{}
	}

	if o.caFile != "" || o.caPath != "" {
		pool := x509.NewCertPool()
		if cfg.RootCAs != nil {
			pool = cfg.RootCAs.Clone()
		}
		if o.caFile != "" {
			if err := loadCAFile(pool, o.caFile); err != nil {
				return nil, err
			}
		}
		if o.caPath != "" {
			if err := loadCAPath(pool, o.caPath); err != nil {
				return nil, err
			}
		}
		cfg.RootCAs = pool
	}

	if o.certFile != "" || o.keyFile != "" {
		if o.certFile == "" || o.keyFile == "" {
			return nil, errors.New("client certificate and key must be set together")
		}
		cert, err := tls.LoadX509KeyPair(o.certFile, o.keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		cfg.Certificates = append(slices.Clone(cfg.Certificates), cert)
	}

	if o.serverName != "" {
		cfg.ServerName = o.serverName
	}
	if o.skipVerify {
		// Explicit caller opt-in via WithTLSSkipVerify; intended for
		// development against self-signed deployments.
		cfg.InsecureSkipVerify = true
	}

	return cfg, nil
}

// loadCAFile appends the certificates of one PEM file to pool.
func loadCAFile(pool *x509.CertPool, path string) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading ca certificate file %q: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("no certificates found in ca certificate file %q", path)
	}
	return nil
}

// loadCAPath walks dir recursively and appends every certificate found in its
// regular files to pool. Directories and other non-regular entries are
// skipped, files without PEM certificates are ignored, and it is an error
// when the walk yields no certificate at all. The walk is confined to dir
// through [os.Root], so symbolic links pointing outside it are not followed.
func loadCAPath(pool *x509.CertPool, dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("reading ca certificate directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	fsys := root.FS()
	var added bool
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := fs.Stat(fsys, path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		if pool.AppendCertsFromPEM(data) {
			added = true
		}
		return nil
	}
	if err := fs.WalkDir(fsys, ".", walk); err != nil {
		return fmt.Errorf("reading ca certificate directory %q: %w", dir, err)
	}
	if !added {
		return fmt.Errorf("no certificates found in ca certificate directory %q", dir)
	}
	return nil
}

// newManagedHTTPClient builds the SDK-managed *http.Client: the configured
// timeout on a clone of http.DefaultTransport (keeping proxy settings,
// handshake timeouts, connection pooling and HTTP/2) with the TLS options
// applied. When the TLS material cannot be loaded, the returned client refuses
// every request with that error so the misconfiguration cannot be bypassed;
// [Client.Connect] reports the same error first.
func (c *Client) newManagedHTTPClient() (*http.Client, error) {
	hc := &http.Client{Timeout: c.timeout}
	if !c.tlsOpts.configured() {
		return hc, nil
	}
	if c.tlsOpts.skipVerify && c.tlsOpts.hasTrustMaterial() {
		c.logger.Warn("WithTLSSkipVerify disables certificate verification; the CA certificates and server name from the other WithTLS* options are not checked")
	}

	cfg, err := c.tlsOpts.build()
	if err != nil {
		hc.Transport = failingTransport{err: err}
		return hc, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = cfg
	hc.Transport = transport
	return hc, nil
}

// failingTransport is installed when TLS material could not be loaded. It
// fails every request with the load error instead of silently falling back to
// the system trust store.
type failingTransport struct{ err error }

// RoundTrip implements http.RoundTripper by returning the stored error.
func (t failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}
