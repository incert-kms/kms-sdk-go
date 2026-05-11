package kmssdk

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	client := NewClient(context.Background(), WithBaseURL(srv.URL))
	client.oauth2 = &Oauth2{
		httpClient:        client.httpClient,
		accessToken:       "test-token",
		accessTokenExpiry: time.Now().Add(time.Hour),
		logger:            slog.New(slog.DiscardHandler),
	}
	return client, srv
}

func TestNewClient_defaults(t *testing.T) {
	c := NewClient(context.Background())
	if c.baseURL != defaultBaseURL {
		t.Errorf("expected base URL %s, got %s", defaultBaseURL, c.baseURL)
	}
	if c.httpClient == nil {
		t.Error("expected httpClient to be initialized")
	}
}

func TestClient_authorizationHeader(t *testing.T) {
	var gotAuth string
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
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
		if r.URL.RequestURI() != "/vslots?size=10000" {
			t.Errorf("request URI = %s, want /vslots?size=10000", r.URL.RequestURI())
		}
		if got, want := r.Header.Get("Authorization"), "Bearer test-token"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		json.NewEncoder(w).Encode(pagedResponse[Vslot]{
			Content: []Vslot{{ID: vslotID, Provider: providerID, ProviderName: "kc"}},
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

func TestClient_GetKeys(t *testing.T) {
	vslotID := uuid.New()
	keyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/keys" {
			t.Errorf("path = %s, want /keys", r.URL.Path)
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
			Content: []KeySearchResult{{ID: keyID, Name: "my-key", Alg: "AES256"}},
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
					Content: []KeySearchResult{{Name: "match"}},
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
		wantPath := "/keys/" + keyID.String()
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
		wantPath := "/vslots/" + vslotID.String() + "/p/kg"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if r.URL.Query().Get("async") != "false" {
			t.Errorf("async = %q, want false", r.URL.Query().Get("async"))
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.key+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req KeyDetail
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if req.Alg != "AES256" || req.Name != "test-key" || req.Persistence != "EXTERNAL" {
			t.Errorf("request body = %+v, want Alg=AES256 Name=test-key Persistence=EXTERNAL", req)
		}
		json.NewEncoder(w).Encode(struct {
			ID uuid.UUID `json:"id"`
		}{ID: newKeyID})
	})

	in := KeyDetail{Alg: "AES256", Name: "test-key", Persistence: "EXTERNAL"}
	got, err := client.CreateKey(context.Background(), in, vslotID)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if got.ID != newKeyID {
		t.Errorf("ID = %s, want %s", got.ID, newKeyID)
	}
	if got.Alg != "AES256" || got.Name != "test-key" || got.Persistence != "EXTERNAL" {
		t.Errorf("returned key did not preserve input fields: %+v", got)
	}
}

func TestClient_DeleteKey(t *testing.T) {
	keyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/keys/" + keyID.String() + "/state"
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
		{"encrypt", OperationEncrypt, "/keys/" + keyID.String() + "/p/encrypt", plaintext, ciphertext},
		{"decrypt", OperationDecrypt, "/keys/" + keyID.String() + "/p/decrypt", ciphertext, plaintext},
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
				var req CryptoRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decoding request body: %v", err)
				}
				if !bytes.Equal(req.Data, tc.inData) {
					t.Errorf("request Data = %x, want %x", req.Data, tc.inData)
				}
				if req.Algorithm != "AES_GCM" {
					t.Errorf("Algorithm = %q, want AES_GCM", req.Algorithm)
				}
				if !bytes.Equal(req.Attributes.IV, iv) {
					t.Errorf("Attributes.IV = %x, want %x", req.Attributes.IV, iv)
				}
				json.NewEncoder(w).Encode(struct {
					Data []byte `json:"data"`
				}{Data: tc.respData})
			})

			got, err := client.Crypto(context.Background(), tc.op, keyID, CryptoRequest{
				Data:       tc.inData,
				Algorithm:  "AES_GCM",
				Attributes: Attributes{IV: iv},
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
