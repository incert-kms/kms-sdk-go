package kmssdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// selfManagedAuth is the TokenSource for SELF_MANAGED deployments, where
// Keys&More issues its own JWTs through the TOKEN API (POST {base}/auth/token
// and friends). It logs in with username/password, caches the token pair, and
// renews the access token with the refresh endpoint, falling back to a fresh
// login when the refresh is rejected.
type selfManagedAuth struct {
	baseURL    string // KMS API root ("<base>/api"), derived by the Client
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

func newSelfManagedAuth(baseURL string, httpClient *http.Client, username, password string, logger *slog.Logger) *selfManagedAuth {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	return &selfManagedAuth{
		baseURL:    baseURL,
		httpClient: httpClient,
		username:   username,
		password:   password,
		logger:     logger,
	}
}

// GetToken returns the cached access token when still valid, otherwise renews
// it via POST /auth/token/refresh (falling back to a fresh login when the
// refresh token is missing, expired, or rejected). Safe for concurrent use.
func (s *selfManagedAuth) GetToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.accessToken != "" && time.Now().Before(s.accessTokenExpiry) {
		s.logger.Debug("using cached access token",
			"expires_at", s.accessTokenExpiry.Format(time.RFC3339),
			"remaining", time.Until(s.accessTokenExpiry).Round(time.Second),
		)
		return s.accessToken, nil
	}

	if s.refreshToken != "" && time.Now().Before(s.refreshTokenExpiry) {
		s.logger.Debug("using refresh token",
			"expires_at", s.refreshTokenExpiry.Format(time.RFC3339),
			"remaining", time.Until(s.refreshTokenExpiry).Round(time.Second),
		)
		token, err := s.requestToken(ctx, "/auth/token/refresh", struct {
			RefreshToken string `json:"refresh_token"`
		}{RefreshToken: s.refreshToken})
		if err == nil {
			return token, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode >= 500 {
			return "", err
		}
		// The refresh token was rejected (deactivated, expired server-side,
		// ...): drop it and fall back to a fresh login.
		s.logger.Debug("token refresh rejected, falling back to login", "error", err)
		s.refreshToken = ""
	}

	s.logger.Debug("logging in", "username", s.username)
	return s.requestToken(ctx, "/auth/token", struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: s.username, Password: s.password})
}

// InvalidateToken drops the cached access token so that the next GetToken call
// obtains a fresh one. The client calls this when the server rejects a request
// with 401 (e.g. a token deactivated before its local expiry).
func (s *selfManagedAuth) InvalidateToken() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToken = ""
}

// Logout deactivates the cached access and refresh tokens server-side
// (POST /auth/token/logout) and clears the local cache. It is a no-op when no
// tokens are cached.
func (s *selfManagedAuth) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.accessToken == "" && s.refreshToken == "" {
		return nil
	}

	body, err := json.Marshal(struct { //nolint:gosec // the logout endpoint's documented body is the tokens to deactivate
		AccessToken  string `json:"access_token,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}{AccessToken: s.accessToken, RefreshToken: s.refreshToken})
	if err != nil {
		return fmt.Errorf("marshaling logout request: %w", err)
	}

	resp, err := s.post(ctx, "/auth/token/logout", body)
	if err != nil {
		return fmt.Errorf("executing logout request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return newAPIError(resp, "error logging out")
	}

	s.accessToken = ""
	s.refreshToken = ""
	return nil
}

// requestToken posts the given payload to a token endpoint and caches the
// resulting tokens. A refresh response carries no new refresh token; the one
// obtained at login is kept in that case. The caller must hold s.mu.
func (s *selfManagedAuth) requestToken(ctx context.Context, path string, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling token request: %w", err)
	}

	resp, err := s.post(ctx, path, body)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return "", newAPIError(resp, "error getting token")
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	s.accessToken = tr.AccessToken
	s.accessTokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)

	if tr.RefreshToken != "" {
		s.refreshToken = tr.RefreshToken
		s.refreshTokenExpiry = time.Now().Add(time.Duration(tr.RefreshExpiresIn) * time.Second)
	}

	return s.accessToken, nil
}

func (s *selfManagedAuth) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return s.httpClient.Do(req)
}
