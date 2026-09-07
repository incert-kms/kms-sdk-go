package kmssdk

import (
	"cmp"
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
	"unicode"
)

// defaultAccessTokenProperty is the token-response property read when the
// discovery config does not name one.
const defaultAccessTokenProperty = "accessToken"

// oidcAuth is the generic-OIDC TokenSource for OAUTH2 deployments with
// provider OTHER (Auth0, Okta, ...): resource-owner password grant against the
// token endpoint from discovery, renewal with the refresh-token grant when the
// IdP issued a refresh token, and password-grant fallback when the refresh is
// rejected. There is no server-side logout flow for these providers;
// [Client.Logout] drops the cached token locally.
type oidcAuth struct {
	tokenURL      string // resolved absolute token endpoint
	clientID      string
	clientSecret  string // optional (WithClientSecret), for confidential clients
	audience      string // optional, sent on the password grant when set
	tokenProperty string // discovery accessTokenProperty; empty means accessToken
	httpClient    *http.Client
	username      string
	password      string
	logger        *slog.Logger

	mu                sync.Mutex
	accessToken       string
	accessTokenExpiry time.Time // zero when the IdP reported no expires_in
	refreshToken      string
}

func newOIDCAuth(cfg *OAuth2OtherConfig, tokenURL string, httpClient *http.Client, username, password, clientSecret string, logger *slog.Logger) *oidcAuth {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	return &oidcAuth{
		tokenURL:      tokenURL,
		clientID:      cfg.ClientID,
		clientSecret:  clientSecret,
		audience:      cfg.Audience,
		tokenProperty: cfg.AccessTokenProperty,
		httpClient:    httpClient,
		username:      username,
		password:      password,
		logger:        logger,
	}
}

// GetToken returns the cached access token when still valid, otherwise renews
// it via the refresh-token grant (falling back to the password grant when the
// refresh token is missing or rejected). A token the IdP issued without an
// expiry is cached until the server rejects it — the 401 replay corrects
// that. Safe for concurrent use.
func (o *oidcAuth) GetToken(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.accessToken != "" && (o.accessTokenExpiry.IsZero() || time.Now().Before(o.accessTokenExpiry)) {
		return o.accessToken, nil
	}

	if o.refreshToken != "" {
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

	o.logger.Debug("getting new access token", "client_id", o.clientID, "username", o.username)
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {o.clientID},
		"username":   {o.username},
		"password":   {o.password},
		"scope":      {"openid"},
	}
	if o.audience != "" {
		form.Set("audience", o.audience)
	}
	return o.requestToken(ctx, form)
}

// InvalidateToken drops the cached access token so that the next GetToken call
// obtains a fresh one. The client calls this when the server rejects a request
// with 401 (e.g. a token revoked before its local expiry).
func (o *oidcAuth) InvalidateToken() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.accessToken = ""
}

// requestToken posts the given grant to the token endpoint, adding the client
// secret when configured, and caches the resulting tokens. The caller must
// hold o.mu.
func (o *oidcAuth) requestToken(ctx context.Context, form url.Values) (string, error) {
	if o.clientSecret != "" {
		form.Set("client_secret", o.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.httpClient.Do(req)
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

	// The response shape is IdP-specific: decode generically and pick the
	// property named by the discovery config.
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	var token string
	candidates := tokenPropertyCandidates(o.tokenProperty)
	for _, name := range candidates {
		if s, ok := raw[name].(string); ok && s != "" {
			token = s
			break
		}
	}
	if token == "" {
		return "", fmt.Errorf("token response carries no %s property (tried %s)",
			cmp.Or(o.tokenProperty, defaultAccessTokenProperty), strings.Join(candidates, ", "))
	}

	o.accessToken = token
	o.accessTokenExpiry = time.Time{}
	if expiresIn, ok := raw["expires_in"].(float64); ok && expiresIn > 0 {
		o.accessTokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	if refresh, ok := raw["refresh_token"].(string); ok && refresh != "" {
		o.refreshToken = refresh
	}

	return o.accessToken, nil
}

// tokenPropertyCandidates returns the JSON property names to try in a token
// response for the discovery accessTokenProperty, which is camel-case
// ("accessToken", "idToken") while the wire is snake_case (access_token,
// id_token). The literal spelling is tried first, then the snake_case form.
func tokenPropertyCandidates(property string) []string {
	if property == "" {
		property = defaultAccessTokenProperty
	}
	snake := camelToSnake(property)
	if snake == property {
		return []string{property}
	}
	return []string{property, snake}
}

// camelToSnake converts a camel-case identifier to snake_case
// ("accessToken" → "access_token").
func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
