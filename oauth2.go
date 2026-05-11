package kmssdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultRealm = "kms"
const defaultClientID = "kms"

type Oauth2 struct {
	authType           AuthenticationType
	authProvider       Oauth2Provider
	baseURL            string
	httpClient         *http.Client
	username           string
	password           string
	accessToken        string
	accessTokenExpiry  time.Time
	refreshToken       string
	refreshTokenExpiry time.Time
	logger             *slog.Logger
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

func NewOauth2(baseURL string, httpClient *http.Client, username, password string, logger *slog.Logger) *Oauth2 {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	return &Oauth2{
		baseURL:      baseURL,
		httpClient:   httpClient,
		authType:     AuthenticationTypeOAuth2,
		authProvider: Oauth2ProviderKeycloak,
		username:     username,
		password:     password,
		logger:       logger,
	}
}

func (o *Oauth2) GetToken(ctx context.Context) (string, error) {
	if o.accessToken != "" && time.Now().Before(o.accessTokenExpiry) {
		o.logger.Debug("using cached access token",
			"expires_at", o.accessTokenExpiry.Format(time.RFC3339),
			"remaining", time.Until(o.accessTokenExpiry).Round(time.Second),
		)
		return o.accessToken, nil
	}

	tokenURL := o.baseURL + "/realms/" + defaultRealm + "/protocol/openid-connect/token"

	var form url.Values
	if o.refreshToken != "" && time.Now().Before(o.refreshTokenExpiry) {
		o.logger.Debug("using refresh token",
			"expires_at", o.refreshTokenExpiry.Format(time.RFC3339),
			"remaining", time.Until(o.refreshTokenExpiry).Round(time.Second),
		)
		form = url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {defaultClientID},
			"refresh_token": {o.refreshToken},
		}
	} else {
		o.logger.Debug("getting new access token",
			"client_id", defaultClientID,
			"username", o.username,
		)
		form = url.Values{
			"grant_type": {"password"},
			"client_id":  {defaultClientID},
			"username":   {o.username},
			"password":   {o.password},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer resp.Body.Close()

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
