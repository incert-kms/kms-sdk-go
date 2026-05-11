package kmssdk

import (
	"crypto/tls"
	"log/slog"
	"net/http"
)

type Option func(*Client)

func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = url }
}

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

func WithTLSSkipVerify() Option {
	return func(c *Client) {
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicit caller opt-in via WithTLSSkipVerify; intended for dev/self-signed environments
		}
	}
}

func WithUsernameAndPassword(username, password string) Option {
	return func(c *Client) {
		c.username = username
		c.password = password
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		c.logger = logger
	}
}
