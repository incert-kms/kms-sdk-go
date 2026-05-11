package kmssdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultBaseURL = "https://kms-uat.incert.lu/kms/api"
const maxRecords = 10000 // max number of records returned by the API

type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	oauth2     *Oauth2
	logger     *slog.Logger
}

func NewClient(ctx context.Context, opts ...Option) *Client {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	c := &Client{
		httpClient: httpClient,
		baseURL:    defaultBaseURL,
		logger:     slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) Connect(ctx context.Context) error {
	// Get the auth config from KMS
	config, err := c.getConfig(ctx)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	// Create the oauth2 client based on the config
	// In this version we only support Keycloak
	kcURL := config.Oauth2.Keycloak.URL
	var keyCloakBaseUrl string
	if strings.HasPrefix(kcURL, "http://") || strings.HasPrefix(kcURL, "https://") {
		keyCloakBaseUrl = kcURL
	} else if strings.HasPrefix(kcURL, "/") {
		parsed, err := url.Parse(c.baseURL)
		if err != nil {
			return fmt.Errorf("parsing base url: %w", err)
		}
		keyCloakBaseUrl = parsed.Scheme + "://" + parsed.Host + kcURL
	} else {
		keyCloakBaseUrl = c.baseURL + "/" + kcURL
	}
	c.oauth2 = NewOauth2(keyCloakBaseUrl, c.httpClient, c.username, c.password, c.logger)
	_, err = c.oauth2.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("getting oauth2 token: %w", err)
	}

	// Test authenticated access to the API
	_, err = c.GetVSlots(ctx)
	if err != nil {
		return fmt.Errorf("getting vslots: %w", err)
	}

	return nil
}

func (c *Client) getConfig(ctx context.Context) (*Config, error) {
	var result Config
	if err := c.do(ctx, http.MethodGet, "/configs/auth", nil, false, &result); err != nil {
		return nil, err
	}
	if result.Type != AuthenticationTypeOAuth2 {
		return nil, fmt.Errorf("unsupported authentication type: %s", result.Type)
	}
	if result.Oauth2.Provider != Oauth2ProviderKeycloak {
		return nil, fmt.Errorf("unsupported oauth2 provider: %s", result.Oauth2.Provider)
	}

	return &result, nil
}

func (c *Client) GetVSlots(ctx context.Context) ([]Vslot, error) {
	var result pagedResponse[Vslot]
	if err := c.do(ctx, http.MethodGet, "/vslots?size="+strconv.Itoa(maxRecords), nil, true, &result); err != nil {
		return nil, err
	}

	if result.TotalPages > maxRecords {
		c.logger.Warn("too many vslots (>10.000), some of them may not be returned")
	}

	return result.Content, nil
}

func (c *Client) GetKeys(ctx context.Context, vslotId uuid.UUID) ([]KeySearchResult, error) {
	return c.FindKeys(ctx, vslotId, KeyFilter{})
}

func (c *Client) FindKeys(ctx context.Context, vslotId uuid.UUID, filter KeyFilter) ([]KeySearchResult, error) {
	var result pagedResponse[KeySearchResult]

	query := url.Values{}
	query.Set("size", strconv.Itoa(maxRecords))
	query.Set("vslotId", vslotId.String())
	query.Set("sort", "creationDate,desc")
	if filter.Name != "" {
		query.Set("name", filter.Name)
	}
	if filter.ID != uuid.Nil {
		query.Set("id", filter.ID.String())
	}

	if err := c.do(ctx, http.MethodGet, "/keys?"+query.Encode(), nil, true, &result); err != nil {
		return nil, err
	}

	if result.TotalPages > maxRecords {
		c.logger.Warn("too many keys in vslot (>10.000), sme keys may not be returned")
	}

	return result.Content, nil
}

func (c *Client) GetKey(ctx context.Context, keyId uuid.UUID) (KeyDetail, error) {
	var result KeyDetail
	if err := c.do(ctx, http.MethodGet, "/keys/"+keyId.String(), nil, true, &result); err != nil {
		return KeyDetail{}, err
	}
	return result, nil
}

func (c *Client) CreateKey(ctx context.Context, key KeyDetail, vslotId uuid.UUID) (KeyDetail, error) {
	var result struct {
		ID uuid.UUID `json:"id"`
	}

	body, err := json.Marshal(key)
	if err != nil {
		return KeyDetail{}, fmt.Errorf("marshaling key: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/vslots/"+vslotId.String()+"/p/kg?async=false", bytes.NewReader(body), true, &result, "application/kms.key+json"); err != nil {
		return KeyDetail{}, err
	}

	key.ID = result.ID
	return key, nil
}

func (c *Client) DeleteKey(ctx context.Context, keyID uuid.UUID) error {
	body, err := json.Marshal(struct {
		State string `json:"state"`
	}{State: "DELETED"})
	if err != nil {
		return fmt.Errorf("marshaling delete request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/state", bytes.NewReader(body), true, nil); err != nil {
		return err
	}
	return nil
}

func (c *Client) Crypto(ctx context.Context, op CryptoOperation, keyID uuid.UUID, request CryptoRequest) ([]byte, error) {
	var result struct {
		Data []byte `json:"data"`
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling %s request: %w", op, err)
	}

	path := "/keys/" + keyID.String() + "/p/" + string(op)
	contentType := "application/kms.encrypt+json"

	if err := c.do(ctx, http.MethodPost, path, bytes.NewReader(body), true, &result, contentType); err != nil {
		return nil, err
	}

	return result.Data, nil
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, authenticated bool, result any, contentType ...string) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	if authenticated {
		token, err := c.oauth2.GetToken(ctx)
		if err != nil {
			return fmt.Errorf("getting oauth2 token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	requestContentType := "application/json"
	if len(contentType) > 0 && contentType[0] != "" {
		requestContentType = contentType[0]
	}
	req.Header.Set("Content-Type", requestContentType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return newAPIError(resp)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}
