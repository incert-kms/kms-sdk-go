package kmssdk

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Option configures a [Client] during [NewClient].
type Option func(*Client)

// WithBaseURL overrides the default base URL of the Keys&More deployment,
// e.g. "https://kms.example.com/kms". The /api prefix common to every REST
// path is appended internally and must NOT be part of the URL; a trailing
// slash is removed.
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(url, "/") }
}

// WithHTTPClient supplies a custom *http.Client, replacing the SDK-managed one.
// It takes precedence over [WithTimeout] and every WithTLS* option (a warning
// is logged when both are given): configure timeouts and TLS on the custom
// client directly.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout sets the overall timeout of the SDK-managed HTTP client
// (default 10s). It covers the full request including reading the response
// body; raise it when running synchronous key generation against slow
// providers. Ignored when [WithHTTPClient] is used.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithTLSSkipVerify disables TLS certificate verification on the SDK-managed
// HTTP client, including verification against the anchors from
// [WithTLSCACert] and [WithTLSCAPath]. Development only — never use it in
// production. Ignored (with a logged warning) when [WithHTTPClient] is used.
func WithTLSSkipVerify() Option {
	return func(c *Client) { c.tlsOpts.skipVerify = true }
}

// WithTLSCACert sets the PEM file whose certificates become the trust anchors
// of the SDK-managed HTTP client, replacing the system roots. The same
// transport carries the identity provider's token requests, so those are
// verified against these anchors too. The file is read by [NewClient]; a read
// or parse failure is reported by [Client.Connect] before any request is
// made. Ignored (with a logged warning) when [WithHTTPClient] is used.
func WithTLSCACert(path string) Option {
	return func(c *Client) { c.tlsOpts.caFile = path }
}

// WithTLSCAPath sets a directory of PEM files whose certificates become the
// trust anchors of the SDK-managed HTTP client, replacing the system roots.
// The directory is walked recursively; files without PEM certificates are
// skipped, and it is an error when no certificate is found at all. It
// combines with [WithTLSCACert]. Ignored (with a logged warning) when
// [WithHTTPClient] is used.
func WithTLSCAPath(dir string) Option {
	return func(c *Client) { c.tlsOpts.caPath = dir }
}

// WithTLSClientCert sets the PEM-encoded certificate and private key files
// the SDK-managed HTTP client presents for mutual TLS. Both must be given;
// they are loaded by [NewClient] and a failure is reported by
// [Client.Connect]. Ignored (with a logged warning) when [WithHTTPClient] is
// used.
func WithTLSClientCert(certFile, keyFile string) Option {
	return func(c *Client) {
		c.tlsOpts.certFile = certFile
		c.tlsOpts.keyFile = keyFile
	}
}

// WithTLSServerName sets the server name sent in the TLS handshake (SNI) and
// verified against the server certificate, for deployments reached through
// an address that differs from the certificate's names. Combined with
// [WithTLSSkipVerify] it only affects SNI. Ignored (with a logged warning)
// when [WithHTTPClient] is used.
func WithTLSServerName(name string) Option {
	return func(c *Client) { c.tlsOpts.serverName = name }
}

// WithTLSConfig supplies a base *tls.Config for the SDK-managed HTTP client,
// for settings the other WithTLS* options do not cover (cipher suites,
// minimum version, in-memory certificates, ...). The config is cloned and the
// other WithTLS* options layer onto the clone: CA material is added to its
// RootCAs, the client certificate is appended to its Certificates, and the
// server name and skip-verify flag are set when given. A nil config is
// ignored. Ignored (with a logged warning) when [WithHTTPClient] is used.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *Client) { c.tlsOpts.base = cfg.Clone() }
}

// WithUsernameAndPassword sets the credentials used for the OAuth2 password
// grant during [Client.Connect].
func WithUsernameAndPassword(username, password string) Option {
	return func(c *Client) {
		c.username = username
		c.password = password
	}
}

// WithClientSecret sets the OAuth2 client secret sent to the identity
// provider's token endpoint. It is currently used only on deployments with
// provider OTHER (generic OIDC), where confidential clients (e.g. Auth0)
// require one; leave it unset for public clients.
func WithClientSecret(secret string) Option {
	return func(c *Client) { c.clientSecret = secret }
}

// WithLogger supplies a *slog.Logger for diagnostic output; without it the SDK
// is silent.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		c.logger = logger
	}
}
