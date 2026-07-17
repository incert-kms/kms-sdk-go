package kmssdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// helper: create a client pointed at a fake server with a pre-injected oauth2
// token so authenticated requests don't hit a real Keycloak.
func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := NewClient(WithBaseURL(srv.URL))
	client.tokenSource = &oauth2{
		httpClient:        client.httpClient,
		accessToken:       "test-token",
		accessTokenExpiry: time.Now().Add(time.Hour),
		logger:            slog.New(slog.DiscardHandler),
	}
	return client, srv
}

func TestNewClient_defaults(t *testing.T) {
	c := NewClient()
	if c.baseURL != defaultBaseURL {
		t.Errorf("expected base URL %s, got %s", defaultBaseURL, c.baseURL)
	}
	if c.httpClient == nil {
		t.Error("expected httpClient to be initialized")
	}
	if c.httpClient.Timeout != defaultTimeout {
		t.Errorf("timeout = %s, want %s", c.httpClient.Timeout, defaultTimeout)
	}
}

func TestNewClient_options(t *testing.T) {
	c := NewClient(WithBaseURL("https://kms.example.com/kms/"), WithTimeout(42*time.Second))
	if c.baseURL != "https://kms.example.com/kms" {
		t.Errorf("trailing slash not trimmed: %s", c.baseURL)
	}
	if c.apiURL != "https://kms.example.com/kms/api" {
		t.Errorf("apiURL = %s, want the base URL with /api appended", c.apiURL)
	}
	if c.httpClient.Timeout != 42*time.Second {
		t.Errorf("timeout = %s, want 42s", c.httpClient.Timeout)
	}

	hc := &http.Client{}
	c = NewClient(WithHTTPClient(hc), WithTLSSkipVerify())
	if c.httpClient != hc {
		t.Error("custom http client not installed")
	}
	if hc.Transport != nil {
		t.Error("WithTLSSkipVerify must not mutate a caller-supplied client")
	}
}

func TestClient_notConnected(t *testing.T) {
	c := NewClient()
	_, err := c.GetVSlots(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected not-connected error, got %v", err)
	}
}

func TestClient_authorizationHeader(t *testing.T) {
	var gotAuth string
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if got, want := r.Header.Get("Accept"), "application/json"; got != want {
			t.Errorf("Accept = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
	})

	if err := client.do(context.Background(), http.MethodGet, "/anything", nil, true, nil); err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	if want := "Bearer test-token"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}

	gotAuth = ""
	if err := client.do(context.Background(), http.MethodGet, "/anything", nil, false, nil); err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("expected no Authorization header on unauthenticated request, got %q", gotAuth)
	}
}

func TestClient_apiError(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "not found",
			"code":    "resource_missing",
		})
	})

	err := client.do(context.Background(), http.MethodGet, "/missing", nil, false, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 404 {
		t.Errorf("status = %d, want 404", apiErr.StatusCode)
	}
}

func errorResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     strconv.Itoa(status) + " " + http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestNewAPIError_bodyShapes(t *testing.T) {
	t.Run("standard ApiErrorModel", func(t *testing.T) {
		err := newAPIError(errorResponse(404, `{"code":"RESOURCE_NOT_FOUND","message":"Key not found","errors":null}`))
		apiErr := err.(*APIError)
		if apiErr.Code != ErrCodeResourceNotFound {
			t.Errorf("Code = %q, want RESOURCE_NOT_FOUND", apiErr.Code)
		}
		if apiErr.Message != "Key not found" {
			t.Errorf("Message = %q", apiErr.Message)
		}
	})

	t.Run("validation errors list", func(t *testing.T) {
		err := newAPIError(errorResponse(400, `{"code":"BAD_REQUEST","message":"The request contains invalid arguments","errors":["Error on the field 'universe' : must not be null"]}`))
		apiErr := err.(*APIError)
		if len(apiErr.Errors) != 1 || !strings.Contains(apiErr.Errors[0], "universe") {
			t.Errorf("Errors = %v, want one field message", apiErr.Errors)
		}
	})

	t.Run("framework fallback keeps message", func(t *testing.T) {
		err := newAPIError(errorResponse(400, `{"timestamp":"2026-07-16T12:00:00.000+02:00","status":400,"error":"400 BAD_REQUEST","message":"Invalid value 'FOO' for field 'state'"}`))
		apiErr := err.(*APIError)
		if apiErr.Message != "Invalid value 'FOO' for field 'state'" {
			t.Errorf("Message clobbered: %q", apiErr.Message)
		}
	})

	t.Run("keycloak error folded when no message", func(t *testing.T) {
		err := newAPIError(errorResponse(401, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`))
		apiErr := err.(*APIError)
		if apiErr.Message != "invalid_grant (Invalid user credentials)" {
			t.Errorf("Message = %q", apiErr.Message)
		}
	})

	t.Run("non-JSON body falls back to HTTP status", func(t *testing.T) {
		err := newAPIError(errorResponse(502, `<html>bad gateway</html>`))
		apiErr := err.(*APIError)
		if apiErr.Message != "502 Bad Gateway" || apiErr.Code != "Bad Gateway" {
			t.Errorf("got Message=%q Code=%q", apiErr.Message, apiErr.Code)
		}
	})

	t.Run("caller fallback message used when body has none", func(t *testing.T) {
		err := newAPIError(errorResponse(500, `{}`), "error getting token")
		apiErr := err.(*APIError)
		if apiErr.Message != "error getting token" {
			t.Errorf("Message = %q, want fallback", apiErr.Message)
		}
	})
}

func TestClient_successfulDecode(t *testing.T) {
	type Item struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Item{ID: "abc", Name: "thing"})
	})

	var got Item
	err := client.do(context.Background(), http.MethodGet, "/items/abc", nil, false, &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "abc" || got.Name != "thing" {
		t.Errorf("got %+v, want {ID:abc Name:thing}", got)
	}
}

func TestClient_GetVSlots(t *testing.T) {
	vslotID := uuid.New()
	providerID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.RequestURI() != "/api/vslots?page=0&size=10000" {
			t.Errorf("request URI = %s, want /api/vslots?page=0&size=10000", r.URL.RequestURI())
		}
		if got, want := r.Header.Get("Authorization"), "Bearer test-token"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		json.NewEncoder(w).Encode(pagedResponse[Vslot]{
			Content:    []Vslot{{ID: vslotID, Provider: providerID, ProviderName: "kc"}},
			TotalPages: 1,
			Last:       true,
		})
	})

	got, err := client.GetVSlots(context.Background())
	if err != nil {
		t.Fatalf("GetVSlots: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].ID != vslotID {
		t.Errorf("ID = %s, want %s", got[0].ID, vslotID)
	}
	if got[0].ProviderName != "kc" {
		t.Errorf("ProviderName = %s, want kc", got[0].ProviderName)
	}
}

func TestClient_paginationIteratesAllPages(t *testing.T) {
	const totalPages = 3
	var requestedPages []string
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		requestedPages = append(requestedPages, r.URL.Query().Get("page"))
		json.NewEncoder(w).Encode(pagedResponse[Vslot]{
			Content:    []Vslot{{ID: uuid.New()}},
			TotalPages: totalPages,
			Last:       page == totalPages-1,
		})
	})

	got, err := client.GetVSlots(context.Background())
	if err != nil {
		t.Fatalf("GetVSlots: %v", err)
	}
	if len(got) != totalPages {
		t.Errorf("len = %d, want %d (one item per page)", len(got), totalPages)
	}
	if want := []string{"0", "1", "2"}; !equalStrings(requestedPages, want) {
		t.Errorf("requested pages = %v, want %v", requestedPages, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestClient_GetKeys(t *testing.T) {
	vslotID := uuid.New()
	keyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/keys" {
			t.Errorf("path = %s, want /api/keys", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("size") != "10000" {
			t.Errorf("size = %q, want 10000", q.Get("size"))
		}
		if q.Get("vslotId") != vslotID.String() {
			t.Errorf("vslotId = %q, want %s", q.Get("vslotId"), vslotID)
		}
		if q.Get("name") != "" {
			t.Errorf("name should be absent on unfiltered call, got %q", q.Get("name"))
		}
		if q.Get("id") != "" {
			t.Errorf("id should be absent on unfiltered call, got %q", q.Get("id"))
		}
		json.NewEncoder(w).Encode(pagedResponse[KeySearchResult]{
			Content:    []KeySearchResult{{ID: keyID, Name: "my-key", Alg: "AES256"}},
			TotalPages: 1,
			Last:       true,
		})
	})

	got, err := client.GetKeys(context.Background(), vslotID)
	if err != nil {
		t.Fatalf("GetKeys: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Name != "my-key" {
		t.Errorf("Name = %q, want my-key", got[0].Name)
	}
}

func TestClient_FindKeys(t *testing.T) {
	vslotID := uuid.New()
	filterID := uuid.New()

	cases := []struct {
		name     string
		filter   KeyFilter
		wantName string
		wantID   string
	}{
		{"by name", KeyFilter{Name: "foo"}, "foo", ""},
		{"by id", KeyFilter{ID: filterID}, "", filterID.String()},
		{"by name and id", KeyFilter{Name: "foo", ID: filterID}, "foo", filterID.String()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("vslotId") != vslotID.String() {
					t.Errorf("vslotId = %q, want %s", q.Get("vslotId"), vslotID)
				}
				if q.Get("name") != tc.wantName {
					t.Errorf("name = %q, want %q", q.Get("name"), tc.wantName)
				}
				if q.Get("id") != tc.wantID {
					t.Errorf("id = %q, want %q", q.Get("id"), tc.wantID)
				}
				json.NewEncoder(w).Encode(pagedResponse[KeySearchResult]{
					Content:    []KeySearchResult{{Name: "match"}},
					TotalPages: 1,
					Last:       true,
				})
			})

			got, err := client.FindKeys(context.Background(), vslotID, tc.filter)
			if err != nil {
				t.Fatalf("FindKeys: %v", err)
			}
			if len(got) != 1 || got[0].Name != "match" {
				t.Errorf("got %+v, want one key", got)
			}
		})
	}
}

func TestClient_GetKey(t *testing.T) {
	keyID := uuid.New()
	keySize := 256
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		wantPath := "/api/keys/" + keyID.String()
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer test-token"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		json.NewEncoder(w).Encode(KeyDetail{
			ID:            keyID,
			Name:          "single",
			Alg:           "AES256",
			KeySize:       &keySize,
			UseAttributes: &KeyUseAttributes{Sign: true, Encrypt: true},
			Attributes:    map[string]string{"extractable": "false"},
		})
	})

	got, err := client.GetKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.ID != keyID {
		t.Errorf("ID = %s, want %s", got.ID, keyID)
	}
	if got.Name != "single" {
		t.Errorf("Name = %q, want single", got.Name)
	}
	if got.KeySize == nil || *got.KeySize != 256 {
		t.Errorf("KeySize = %v, want *256", got.KeySize)
	}
	if got.UseAttributes == nil || !got.UseAttributes.Sign || !got.UseAttributes.Encrypt {
		t.Errorf("UseAttributes = %+v, want Sign+Encrypt true", got.UseAttributes)
	}
	if got.Attributes["extractable"] != "false" {
		t.Errorf("Attributes[extractable] = %q, want false", got.Attributes["extractable"])
	}
}

func TestClient_CreateKey(t *testing.T) {
	vslotID := uuid.New()
	newKeyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/vslots/" + vslotID.String() + "/p/kg"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if r.URL.Query().Get("async") != "false" {
			t.Errorf("async = %q, want false", r.URL.Query().Get("async"))
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.key+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if req["alg"] != "AES256" || req["name"] != "test-key" || req["persistence"] != "EXTERNAL" {
			t.Errorf("request body = %+v, want alg=AES256 name=test-key persistence=EXTERNAL", req)
		}
		// KeyDataModel carries key material under "values", not "keyValues".
		if _, ok := req["values"]; !ok {
			t.Error("request body missing 'values' field")
		}
		if _, ok := req["keyValues"]; ok {
			t.Error("request body must not contain 'keyValues'")
		}
		// An explicitly false usage flag must reach the server.
		useAttrs, _ := req["useAttributes"].(map[string]any)
		if v, ok := useAttrs["extractable"]; !ok || v != false {
			t.Errorf("useAttributes.extractable = %v, want explicit false", v)
		}
		json.NewEncoder(w).Encode(KeyDataResponse{
			ID:     newKeyID,
			Values: []KeyValue{{Type: "SECRET", Format: "AES_WRAPPED", Value: []byte{0xC0, 0xFE}}},
		})
	})

	in := KeyData{
		Alg:           "AES256",
		Name:          "test-key",
		Persistence:   PersistenceExternal,
		UseAttributes: &KeyUseAttributes{Sign: true, Extractable: false},
		Values:        []KeyValue{{Type: "SECRET", Format: "AES_WRAPPED"}},
	}
	got, err := client.CreateKey(context.Background(), vslotID, in)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if got.ID != newKeyID {
		t.Errorf("ID = %s, want %s", got.ID, newKeyID)
	}
	if len(got.Values) != 1 || !bytes.Equal(got.Values[0].Value, []byte{0xC0, 0xFE}) {
		t.Errorf("returned values not surfaced: %+v", got.Values)
	}
}

func TestClient_DeleteKey(t *testing.T) {
	keyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/keys/" + keyID.String() + "/state"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer test-token"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Content-Type"), "application/json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req struct {
			State string `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if req.State != "DELETED" {
			t.Errorf("state = %q, want DELETED", req.State)
		}
		w.WriteHeader(http.StatusOK)
	})

	if err := client.DeleteKey(context.Background(), keyID); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
}

func TestClient_Crypto(t *testing.T) {
	keyID := uuid.New()
	plaintext := []byte("secret message")
	ciphertext := []byte{0x01, 0x02, 0x03}
	iv := []byte("qqqqqqqqqqqqqqqq")

	cases := []struct {
		name     string
		op       CryptoOperation
		wantPath string
		inData   []byte
		respData []byte
	}{
		{"encrypt", OperationEncrypt, "/api/keys/" + keyID.String() + "/p/encrypt", plaintext, ciphertext},
		{"decrypt", OperationDecrypt, "/api/keys/" + keyID.String() + "/p/decrypt", ciphertext, plaintext},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				if r.URL.Path != tc.wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, tc.wantPath)
				}
				if got, want := r.Header.Get("Content-Type"), "application/kms.encrypt+json"; got != want {
					t.Errorf("Content-Type = %q, want %q", got, want)
				}
				var req struct {
					Data       []byte         `json:"data"`
					Algorithm  string         `json:"algorithm"`
					Attributes map[string]any `json:"attributes"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decoding request body: %v", err)
				}
				if !bytes.Equal(req.Data, tc.inData) {
					t.Errorf("request Data = %x, want %x", req.Data, tc.inData)
				}
				if req.Algorithm != "AES_GCM" {
					t.Errorf("Algorithm = %q, want AES_GCM", req.Algorithm)
				}
				if got, want := req.Attributes["iv"], base64.StdEncoding.EncodeToString(iv); got != want {
					t.Errorf("Attributes.iv = %v, want %q", got, want)
				}
				json.NewEncoder(w).Encode(struct {
					Data []byte `json:"data"`
				}{Data: tc.respData})
			})

			got, err := client.Crypto(context.Background(), tc.op, keyID, CryptoRequest{
				Data:       tc.inData,
				Algorithm:  "AES_GCM",
				Attributes: map[string]any{"iv": iv},
			})
			if err != nil {
				t.Fatalf("Crypto(%s): %v", tc.op, err)
			}
			if !bytes.Equal(got, tc.respData) {
				t.Errorf("got %x, want %x", got, tc.respData)
			}
		})
	}
}

func TestClient_Crypto_rejectsUnknownOperation(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request expected")
	})
	_, err := client.Crypto(context.Background(), CryptoOperation("sign"), uuid.New(), CryptoRequest{})
	if err == nil || !strings.Contains(err.Error(), "unsupported crypto operation") {
		t.Fatalf("expected unsupported-operation error, got %v", err)
	}
}

func keycloakTokenHandler(t *testing.T, wantClientID string, hits *atomic.Int32) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing token form: %v", err)
		}
		if got := r.PostForm.Get("client_id"); got != wantClientID {
			t.Errorf("client_id = %q, want %q", got, wantClientID)
		}
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:      "fresh-token",
			RefreshToken:     "fresh-refresh",
			ExpiresIn:        300,
			RefreshExpiresIn: 1800,
		})
	}
}

func TestConnect_usesDiscoveryRealmAndClientID(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("GET /api/configs/auth", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Config{
			Type: AuthenticationTypeOAuth2,
			OAuth2: &OAuth2Config{
				Provider: OAuth2ProviderKeycloak,
				Keycloak: &OAuth2KeycloakConfig{URL: "/idp", Realm: "myrealm", ClientID: "myclient"},
			},
		})
	})
	mux.HandleFunc("POST /idp/realms/myrealm/protocol/openid-connect/token",
		keycloakTokenHandler(t, "myclient", nil))
	mux.HandleFunc("GET /api/vslots", func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer fresh-token"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		json.NewEncoder(w).Encode(pagedResponse[Vslot]{TotalPages: 1, Last: true})
	})

	client := NewClient(WithBaseURL(srv.URL), WithUsernameAndPassword("u", "p"))
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestConnect_missingOAuth2SectionReturnsError(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Config{Type: AuthenticationTypeOAuth2})
	})
	err := client.Connect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no oauth2 section") {
		t.Fatalf("expected descriptive error, got %v", err)
	}
}

func TestClient_reauthenticatesOnceOn401(t *testing.T) {
	var protectedHits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("POST /realms/kms/protocol/openid-connect/token",
		keycloakTokenHandler(t, "kms", nil))
	mux.HandleFunc("GET /api/protected", func(w http.ResponseWriter, r *http.Request) {
		protectedHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"code": ErrCodeInvalidToken, "message": "revoked"})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	client := NewClient(WithBaseURL(srv.URL))
	source := newOAuth2(srv.URL, "", "", client.httpClient, "u", "p", nil)
	// Seed a token that is still valid locally but revoked server-side.
	source.accessToken = "stale-token"
	source.accessTokenExpiry = time.Now().Add(time.Hour)
	client.tokenSource = source

	if err := client.do(context.Background(), http.MethodGet, "/protected", nil, true, nil); err != nil {
		t.Fatalf("expected replay to succeed, got %v", err)
	}
	if got := protectedHits.Load(); got != 2 {
		t.Errorf("protected endpoint hit %d times, want 2 (401 then replay)", got)
	}
}

func TestOAuth2_refreshFailureFallsBackToPasswordGrant(t *testing.T) {
	var passwordGrants atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		switch r.PostForm.Get("grant_type") {
		case "refresh_token":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Token is not active"})
		case "password":
			passwordGrants.Add(1)
			json.NewEncoder(w).Encode(tokenResponse{AccessToken: "fresh-token", ExpiresIn: 300})
		default:
			t.Errorf("unexpected grant_type %q", r.PostForm.Get("grant_type"))
		}
	}))
	t.Cleanup(srv.Close)

	o := newOAuth2(srv.URL, "", "", srv.Client(), "u", "p", nil)
	o.refreshToken = "revoked-refresh"
	o.refreshTokenExpiry = time.Now().Add(time.Hour)

	token, err := o.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if token != "fresh-token" {
		t.Errorf("token = %q, want fresh-token", token)
	}
	if passwordGrants.Load() != 1 {
		t.Errorf("password grants = %d, want 1", passwordGrants.Load())
	}
	if o.refreshToken != "fresh-refresh" && o.refreshToken != "" {
		t.Errorf("stale refresh token retained: %q", o.refreshToken)
	}
}

func TestOAuth2_concurrentGetTokenFetchesOnce(t *testing.T) {
	var tokenHits atomic.Int32
	srv := httptest.NewServer(keycloakTokenHandler(t, "kms", &tokenHits))
	t.Cleanup(srv.Close)

	o := newOAuth2(srv.URL, "", "", srv.Client(), "u", "p", nil)

	const goroutines = 8
	tokens := make([]string, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens[i], errs[i] = o.GetToken(context.Background())
		}()
	}
	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if tokens[i] != "fresh-token" {
			t.Errorf("goroutine %d token = %q", i, tokens[i])
		}
	}
	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (no refresh stampede)", got)
	}
}

func TestAPIError_errorsAs(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"code": ErrCodeForbiddenAccess, "message": "denied"})
	})

	err := client.do(context.Background(), http.MethodGet, "/thing", nil, false, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As failed on %T", err)
	}
	if apiErr.Code != ErrCodeForbiddenAccess || apiErr.StatusCode != 403 {
		t.Errorf("got Code=%q StatusCode=%d", apiErr.Code, apiErr.StatusCode)
	}
}
