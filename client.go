package kmssdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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

// defaultBaseURL points at INCERT's UAT environment; production deployments
// must set their own base URL with [WithBaseURL]. The /api prefix common to
// every REST path is appended internally.
const defaultBaseURL = "https://kms-uat.incert.lu/kms"
const defaultTimeout = 10 * time.Second
const pageSize = 10000 // page size requested from the paged list endpoints

// Client is a client for the Keys&More KMS HTTP API. Construct it with
// [NewClient], then call [Client.Connect] once before any other method.
//
// After Connect returns, the Client is safe for concurrent use by multiple
// goroutines. Connect itself must complete before concurrent calls start.
type Client struct {
	baseURL     string
	apiURL      string // baseURL + "/api", the root of every REST path
	username    string
	password    string
	httpClient  *http.Client
	tokenSource TokenSource
	logger      *slog.Logger

	timeout       time.Duration
	tlsSkipVerify bool
}

// NewClient creates a Client configured by the given options. It performs no
// I/O; call [Client.Connect] to authenticate against the server.
func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		logger:  slog.New(slog.DiscardHandler),
		timeout: defaultTimeout,
	}
	for _, opt := range opts {
		opt(c)
	}
	c.apiURL = c.baseURL + "/api"

	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: c.timeout}
		if c.tlsSkipVerify {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit caller opt-in via WithTLSSkipVerify; intended for dev/self-signed environments
			c.httpClient.Transport = transport
		}
	} else if c.tlsSkipVerify {
		c.logger.Warn("WithTLSSkipVerify is ignored when WithHTTPClient supplies a custom client; configure TLS on the custom client instead")
	}

	return c
}

// Connect bootstraps authentication: it discovers the authentication
// configuration from the server's public /configs/auth endpoint, sets up the
// matching token backend, obtains a first token, and verifies authenticated
// access with a vslot listing. Supported modes: SELF_MANAGED (tokens issued by
// Keys&More itself) and OAUTH2 with provider KEYCLOAK (password grant).
func (c *Client) Connect(ctx context.Context) error {
	// Get the auth config from KMS
	config, err := c.getConfig(ctx)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	switch config.Type {
	case AuthenticationTypeSelfManaged:
		c.tokenSource = newSelfManagedAuth(c.apiURL, c.httpClient, c.username, c.password, c.logger)
	case AuthenticationTypeOAuth2:
		tokenSource, err := c.newOAuth2FromConfig(config)
		if err != nil {
			return err
		}
		c.tokenSource = tokenSource
	default:
		return fmt.Errorf("unsupported authentication type: %s", config.Type)
	}

	// Obtain a first token (for SELF_MANAGED this performs the login)
	_, err = c.tokenSource.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("getting token: %w", err)
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
	return &result, nil
}

// newOAuth2FromConfig validates the discovered OAuth2 configuration (only the
// Keycloak provider is supported) and builds the Keycloak token backend,
// resolving an absolute, root-relative or relative Keycloak URL against the
// client's base URL.
func (c *Client) newOAuth2FromConfig(config *Config) (TokenSource, error) {
	if config.OAuth2 == nil {
		return nil, errors.New("server config declares OAUTH2 but carries no oauth2 section")
	}
	if config.OAuth2.Provider != OAuth2ProviderKeycloak {
		return nil, fmt.Errorf("unsupported oauth2 provider: %s", config.OAuth2.Provider)
	}
	keycloak := config.OAuth2.Keycloak
	if keycloak == nil {
		return nil, errors.New("server config declares KEYCLOAK but carries no keycloak section")
	}

	kcURL := keycloak.URL
	var keycloakBaseURL string
	if strings.HasPrefix(kcURL, "http://") || strings.HasPrefix(kcURL, "https://") {
		keycloakBaseURL = kcURL
	} else if strings.HasPrefix(kcURL, "/") {
		parsed, err := url.Parse(c.baseURL)
		if err != nil {
			return nil, fmt.Errorf("parsing base url: %w", err)
		}
		keycloakBaseURL = parsed.Scheme + "://" + parsed.Host + strings.TrimSuffix(kcURL, "/")
	} else {
		keycloakBaseURL = c.baseURL + "/" + kcURL
	}
	return newOAuth2(keycloakBaseURL, keycloak.Realm, keycloak.ClientID, c.httpClient, c.username, c.password, c.logger), nil
}

// Logout invalidates the client's cached tokens. On SELF_MANAGED deployments
// the access and refresh tokens are also deactivated server-side
// (POST /auth/token/logout); on OAuth2 deployments the cached token is only
// dropped locally. Calling Logout on a client that never connected is a no-op.
// Further API calls after Logout re-authenticate with the stored credentials.
func (c *Client) Logout(ctx context.Context) error {
	if c.tokenSource == nil {
		return nil
	}
	if lo, ok := c.tokenSource.(interface {
		Logout(ctx context.Context) error
	}); ok {
		return lo.Logout(ctx)
	}
	if invalidator, ok := c.tokenSource.(tokenInvalidator); ok {
		invalidator.InvalidateToken()
	}
	return nil
}

// GetVSlots lists all vslots visible to the authenticated user, iterating
// server pages transparently.
func (c *Client) GetVSlots(ctx context.Context) ([]Vslot, error) {
	return fetchAllPages[Vslot](ctx, c, "/vslots", url.Values{})
}

// GetKeys lists all keys of the given vslot. It is shorthand for
// [Client.FindKeys] with an empty filter.
func (c *Client) GetKeys(ctx context.Context, vslotId uuid.UUID) ([]KeySearchResult, error) {
	return c.FindKeys(ctx, vslotId, KeyFilter{})
}

// FindKeys lists the keys of the given vslot matching the filter, most
// recently created first, iterating server pages transparently. Zero-valued
// filter fields are ignored.
func (c *Client) FindKeys(ctx context.Context, vslotId uuid.UUID, filter KeyFilter) ([]KeySearchResult, error) {
	query := url.Values{}
	query.Set("vslotId", vslotId.String())
	query.Set("sort", "creationDate,desc")
	if filter.Name != "" {
		query.Set("name", filter.Name)
	}
	if filter.ID != uuid.Nil {
		query.Set("id", filter.ID.String())
	}

	return fetchAllPages[KeySearchResult](ctx, c, "/keys", query)
}

// fetchAllPages retrieves every page of a paged list endpoint and returns the
// concatenated content.
func fetchAllPages[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	var all []T
	query.Set("size", strconv.Itoa(pageSize))
	for page := 0; ; page++ {
		query.Set("page", strconv.Itoa(page))
		var result pagedResponse[T]
		if err := c.do(ctx, http.MethodGet, path+"?"+query.Encode(), nil, true, &result); err != nil {
			return nil, err
		}
		all = append(all, result.Content...)
		if result.Last || len(result.Content) == 0 || page >= result.TotalPages-1 {
			return all, nil
		}
	}
}

// GetKey fetches the full representation of a key by its id.
func (c *Client) GetKey(ctx context.Context, keyId uuid.UUID) (KeyDetail, error) {
	var result KeyDetail
	if err := c.do(ctx, http.MethodGet, "/keys/"+keyId.String(), nil, true, &result); err != nil {
		return KeyDetail{}, err
	}
	return result, nil
}

// CreateKey generates a new key in the given vslot (synchronously). The
// response carries the id of the new key and, for persistence NONE, the
// generated material in Values — that response is the only chance to capture
// such material, as it is not stored server-side.
func (c *Client) CreateKey(ctx context.Context, vslotId uuid.UUID, key KeyData) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(key)
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling key: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/vslots/"+vslotId.String()+"/p/kg?async=false", body, true, &result, "application/kms.key+json"); err != nil {
		return KeyDataResponse{}, err
	}

	return result, nil
}

// DeleteKey permanently deletes a key by posting the DELETED lifecycle state:
// the server immediately removes both the key material and its metadata.
func (c *Client) DeleteKey(ctx context.Context, keyID uuid.UUID) error {
	body, err := json.Marshal(struct {
		State string `json:"state"`
	}{State: KeyStateDeleted})
	if err != nil {
		return fmt.Errorf("marshaling delete request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/state", body, true, nil); err != nil {
		return err
	}
	return nil
}

// Crypto performs an encrypt or decrypt operation with the given key and
// returns the resulting bytes. Only [OperationEncrypt] and [OperationDecrypt]
// are supported; other operations (sign, verify, derive, ...) use different
// media types and are not covered by this method.
func (c *Client) Crypto(ctx context.Context, op CryptoOperation, keyID uuid.UUID, request CryptoRequest) ([]byte, error) {
	if op != OperationEncrypt && op != OperationDecrypt {
		return nil, fmt.Errorf("unsupported crypto operation: %s", op)
	}

	var result struct {
		Data []byte `json:"data"`
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling %s request: %w", op, err)
	}

	path := "/keys/" + keyID.String() + "/p/" + string(op)
	contentType := "application/kms.encrypt+json"

	if err := c.do(ctx, http.MethodPost, path, body, true, &result, contentType); err != nil {
		return nil, err
	}

	return result.Data, nil
}

// Sign signs data with the given key and returns the signature bytes. The
// algorithm and its parameters come from the request; see [SignRequest].
func (c *Client) Sign(ctx context.Context, keyID uuid.UUID, request SignRequest) ([]byte, error) {
	var result struct {
		Data []byte `json:"data"`
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling sign request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/sign", body, true, &result, "application/kms.sign+json"); err != nil {
		return nil, err
	}

	return result.Data, nil
}

// Verify checks a signature with the given key. The signature to verify goes
// in request.Attributes.Signature; the result reports validity — a wrong
// signature yields (false, nil), not an error (SignatureVerifiedResponseModel).
func (c *Client) Verify(ctx context.Context, keyID uuid.UUID, request SignRequest) (bool, error) {
	var result struct {
		Valid bool `json:"valid"`
	}

	body, err := json.Marshal(request)
	if err != nil {
		return false, fmt.Errorf("marshaling verify request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/verify", body, true, &result, "application/kms.sign+json"); err != nil {
		return false, err
	}

	return result.Valid, nil
}

// tokenInvalidator is implemented by token sources that can drop their cached
// token, enabling the one-shot re-authentication on 401 responses.
type tokenInvalidator interface {
	InvalidateToken()
}

// errRetryWithFreshToken signals that the request should be replayed once
// after re-authentication.
var errRetryWithFreshToken = errors.New("retry with fresh token")

// do executes one API request. When an authenticated request is rejected with
// 401 (e.g. a token revoked before its local expiry), the cached token is
// invalidated and the request replayed once with a fresh token.
func (c *Client) do(ctx context.Context, method, path string, body []byte, authenticated bool, result any, contentType ...string) error {
	if authenticated && c.tokenSource == nil {
		return errors.New("client not connected: call Connect first")
	}

	for attempt := 0; ; attempt++ {
		req, err := c.newRequest(ctx, method, path, body, authenticated, contentType...)
		if err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("executing request: %w", err)
		}

		err = func() error {
			// Drain any unread body bytes before closing so the keep-alive
			// connection can be reused.
			defer func() {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}()

			if resp.StatusCode == http.StatusUnauthorized && authenticated && attempt == 0 {
				if invalidator, ok := c.tokenSource.(tokenInvalidator); ok {
					invalidator.InvalidateToken()
					c.logger.Debug("request rejected with 401, re-authenticating and retrying once", "path", path)
					return errRetryWithFreshToken
				}
			}

			if resp.StatusCode >= 400 {
				return newAPIError(resp)
			}

			if result != nil {
				if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
					return fmt.Errorf("decoding response: %w", err)
				}
			}
			return nil
		}()
		if errors.Is(err, errRetryWithFreshToken) {
			continue
		}
		return err
	}
}

// newRequest builds one API request: base URL + path, optional JSON body with
// the given content type (default application/json), and a bearer token for
// authenticated calls.
func (c *Client) newRequest(ctx context.Context, method, path string, body []byte, authenticated bool, contentType ...string) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if authenticated {
		token, err := c.tokenSource.GetToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting oauth2 token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		requestContentType := "application/json"
		if len(contentType) > 0 && contentType[0] != "" {
			requestContentType = contentType[0]
		}
		req.Header.Set("Content-Type", requestContentType)
	}
	return req, nil
}
