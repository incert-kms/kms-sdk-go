package kmssdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Fallbacks used when the server's discovery config does not specify a realm
// or client id (conventional deployment defaults).
const defaultRealm = "kms"
const defaultClientID = "kms"

// TokenSource supplies a currently valid bearer token for API requests.
// Implementations must be safe for concurrent use.
type TokenSource interface {
	GetToken(ctx context.Context) (string, error)
}

// oauth2 is the Keycloak-backed TokenSource used by Client.Connect: it obtains
// tokens with the resource-owner password grant, caches them, and renews them
// with the refresh-token grant, falling back to the password grant when the
// refresh is rejected.
type oauth2 struct {
	baseURL    string
	realm      string
	clientID   string
	httpClient *http.Client
	username   string
	password   string
	logger     *slog.Logger

	mu                 sync.Mutex
	accessToken        string
	accessTokenExpiry  time.Time
	refreshToken       string
	refreshTokenExpiry time.Time
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

func newOAuth2(baseURL, realm, clientID string, httpClient *http.Client, username, password string, logger *slog.Logger) *oauth2 {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if realm == "" {
		realm = defaultRealm
	}
	if clientID == "" {
		clientID = defaultClientID
	}

	return &oauth2{
		baseURL:    baseURL,
		realm:      realm,
		clientID:   clientID,
		httpClient: httpClient,
		username:   username,
		password:   password,
		logger:     logger,
	}
}

// GetToken returns the cached access token when still valid, otherwise renews
// it via the refresh-token grant (falling back to the password grant when the
// refresh token is missing, expired, or rejected). Safe for concurrent use.
func (o *oauth2) GetToken(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.accessToken != "" && time.Now().Before(o.accessTokenExpiry) {
		o.logger.Debug("using cached access token",
			"expires_at", o.accessTokenExpiry.Format(time.RFC3339),
			"remaining", time.Until(o.accessTokenExpiry).Round(time.Second),
		)
		return o.accessToken, nil
	}

	if o.refreshToken != "" && time.Now().Before(o.refreshTokenExpiry) {
		o.logger.Debug("using refresh token",
			"expires_at", o.refreshTokenExpiry.Format(time.RFC3339),
			"remaining", time.Until(o.refreshTokenExpiry).Round(time.Second),
		)
		token, err := o.requestToken(ctx, url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {o.clientID},
			"refresh_token": {o.refreshToken},
		})
		if err == nil {
			return token, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode >= 500 {
			return "", err
		}
		// The refresh token was rejected (revoked, expired server-side, ...):
		// drop it and fall back to a fresh password grant.
		o.logger.Debug("refresh grant rejected, falling back to password grant", "error", err)
		o.refreshToken = ""
	}

	o.logger.Debug("getting new access token",
		"client_id", o.clientID,
		"username", o.username,
	)
	return o.requestToken(ctx, url.Values{
		"grant_type": {"password"},
		"client_id":  {o.clientID},
		"username":   {o.username},
		"password":   {o.password},
	})
}

// InvalidateToken drops the cached access token so that the next GetToken call
// obtains a fresh one. The client calls this when the server rejects a request
// with 401 (e.g. a token revoked before its local expiry).
func (o *oauth2) InvalidateToken() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.accessToken = ""
}

// requestToken posts the given grant to the token endpoint and caches the
// resulting tokens. The caller must hold o.mu.
func (o *oauth2) requestToken(ctx context.Context, form url.Values) (string, error) {
	tokenURL := o.baseURL + "/realms/" + o.realm + "/protocol/openid-connect/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return "", newAPIError(resp, "error getting token")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	o.accessToken = tr.AccessToken
	o.accessTokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)

	o.refreshToken = tr.RefreshToken
	o.refreshTokenExpiry = time.Now().Add(time.Duration(tr.RefreshExpiresIn) * time.Second)

	return o.accessToken, nil
}
