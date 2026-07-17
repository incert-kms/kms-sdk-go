package kmssdk

import (
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
// It takes precedence over [WithTimeout] and [WithTLSSkipVerify]: configure
// timeouts and TLS on the custom client directly.
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
// HTTP client. Development only — never use it in production. Ignored (with a
// logged warning) when [WithHTTPClient] is used.
func WithTLSSkipVerify() Option {
	return func(c *Client) { c.tlsSkipVerify = true }
}

// WithUsernameAndPassword sets the credentials used for the OAuth2 password
// grant during [Client.Connect].
func WithUsernameAndPassword(username, password string) Option {
	return func(c *Client) {
		c.username = username
		c.password = password
	}
}

// WithLogger supplies a *slog.Logger for diagnostic output; without it the SDK
// is silent.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		c.logger = logger
	}
}
