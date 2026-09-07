package kmssdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestClient_ExportKey(t *testing.T) {
	keyID := uuid.New()
	wrapKey := []byte{0x01, 0x02, 0x03}
	exported := []byte{0xAA, 0xBB}
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/keys/" + keyID.String() + "/p/export"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.key+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if len(req) != 1 {
			t.Errorf("request body keys = %v, want only 'values'", req)
		}
		values, _ := req["values"].([]any)
		if len(values) != 2 {
			t.Fatalf("values length = %d, want 2", len(values))
		}
		public, _ := values[0].(map[string]any)
		if public["type"] != "PUBLIC" || public["format"] != "OPENSSL_PUBLIC" {
			t.Errorf("values[0] = %v, want PUBLIC/OPENSSL_PUBLIC", public)
		}
		if _, ok := public["wrapKey"]; ok {
			t.Error("values[0] must not carry a wrapKey")
		}
		private, _ := values[1].(map[string]any)
		if private["type"] != "PRIVATE" || private["format"] != "RSAES_OAEP_SHA_256_AES_WRAPPED" {
			t.Errorf("values[1] = %v, want PRIVATE/RSAES_OAEP_SHA_256_AES_WRAPPED", private)
		}
		if got, want := private["wrapKey"], base64.StdEncoding.EncodeToString(wrapKey); got != want {
			t.Errorf("values[1].wrapKey = %v, want %q", got, want)
		}
		json.NewEncoder(w).Encode(KeyDataResponse{
			ID:     keyID,
			Values: []KeyValue{{Type: KeyValueTypePublic, Format: KeyFormatOpenSSLPublic, Value: exported}},
		})
	})

	got, err := client.ExportKey(context.Background(), keyID, []KeyValue{
		{Type: KeyValueTypePublic, Format: KeyFormatOpenSSLPublic},
		{Type: KeyValueTypePrivate, Format: KeyFormatRSAESOAEPSHA256AESWrapped, WrapKey: wrapKey},
	})
	if err != nil {
		t.Fatalf("ExportKey: %v", err)
	}
	if len(got.Values) != 1 || !bytes.Equal(got.Values[0].Value, exported) {
		t.Errorf("exported values not surfaced: %+v", got.Values)
	}
}

func TestClient_EditKey(t *testing.T) {
	keyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/keys/" + keyID.String() + "/p/edit"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.key+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if len(req) != 1 {
			t.Errorf("request body keys = %v, want only 'useAttributes'", req)
		}
		useAttrs, _ := req["useAttributes"].(map[string]any)
		if len(useAttrs) != 8 {
			t.Errorf("useAttributes has %d flags, want all 8", len(useAttrs))
		}
		if useAttrs["sign"] != true {
			t.Errorf("useAttributes.sign = %v, want true", useAttrs["sign"])
		}
		// An explicitly false flag must reach the server.
		if v, ok := useAttrs["extractable"]; !ok || v != false {
			t.Errorf("useAttributes.extractable = %v, want explicit false", v)
		}
		json.NewEncoder(w).Encode(KeyDataResponse{ID: keyID})
	})

	got, err := client.EditKey(context.Background(), keyID, KeyUseAttributes{Sign: true, Verify: true})
	if err != nil {
		t.Fatalf("EditKey: %v", err)
	}
	if got.ID != keyID {
		t.Errorf("ID = %s, want %s", got.ID, keyID)
	}
}

func TestClient_ImportKey(t *testing.T) {
	vslotID := uuid.New()
	newKeyID := uuid.New()
	material := []byte{0x11, 0x22, 0x33}
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/vslots/" + vslotID.String() + "/p/ki"
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
		if req["name"] != "imported" || req["alg"] != "AES128" {
			t.Errorf("request body = %v, want name=imported alg=AES128", req)
		}
		values, _ := req["values"].([]any)
		if len(values) != 1 {
			t.Fatalf("values length = %d, want 1", len(values))
		}
		value, _ := values[0].(map[string]any)
		if value["type"] != "SECRET" || value["format"] != "PLAIN" {
			t.Errorf("values[0] = %v, want SECRET/PLAIN", value)
		}
		if got, want := value["value"], base64.StdEncoding.EncodeToString(material); got != want {
			t.Errorf("values[0].value = %v, want %q", got, want)
		}
		json.NewEncoder(w).Encode(KeyDataResponse{ID: newKeyID})
	})

	got, err := client.ImportKey(context.Background(), vslotID, KeyData{
		Name:   "imported",
		Alg:    "AES128",
		Values: []KeyValue{{Type: KeyValueTypeSecret, Format: KeyFormatPlain, Value: material}},
	})
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if got.ID != newKeyID {
		t.Errorf("ID = %s, want %s", got.ID, newKeyID)
	}
}

func TestClient_ImportKeyValues(t *testing.T) {
	keyID := uuid.New()
	valueID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/keys/" + keyID.String() + "/p/ki"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query = %q, want none", r.URL.RawQuery)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.key+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if len(req) != 1 {
			t.Errorf("request body keys = %v, want only 'values'", req)
		}
		values, _ := req["values"].([]any)
		value, _ := values[0].(map[string]any)
		if value["id"] != valueID.String() || value["format"] != "RSAES_OAEP_SHA_256_WRAPPED" {
			t.Errorf("values[0] = %v, want id %s and RSAES_OAEP_SHA_256_WRAPPED", value, valueID)
		}
		json.NewEncoder(w).Encode(KeyDataResponse{ID: keyID})
	})

	got, err := client.ImportKeyValues(context.Background(), keyID, []KeyValue{
		{ID: valueID, Format: KeyFormatRSAESOAEPSHA256Wrapped, Value: []byte{0x01}},
	})
	if err != nil {
		t.Fatalf("ImportKeyValues: %v", err)
	}
	if got.ID != keyID {
		t.Errorf("ID = %s, want %s", got.ID, keyID)
	}
}

func TestClient_AttachKey(t *testing.T) {
	vslotID := uuid.New()
	newKeyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/vslots/" + vslotID.String() + "/p/ka"
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
		attrs, _ := req["attributes"].(map[string]any)
		if attrs["prov_id"] != "99d773be66fd4e0d9a4e17e593610cae" {
			t.Errorf("attributes.prov_id = %v, want the provider-side hex id", attrs["prov_id"])
		}
		json.NewEncoder(w).Encode(KeyDataResponse{ID: newKeyID})
	})

	got, err := client.AttachKey(context.Background(), vslotID, KeyData{
		Name:       "attach-01",
		Attributes: map[string]string{"prov_id": "99d773be66fd4e0d9a4e17e593610cae"},
	})
	if err != nil {
		t.Fatalf("AttachKey: %v", err)
	}
	if got.ID != newKeyID {
		t.Errorf("ID = %s, want %s", got.ID, newKeyID)
	}
}

func TestClient_importAttach260(t *testing.T) {
	vslotID := uuid.New()
	keyID := uuid.New()

	cases := []struct {
		name string
		call func(c *Client) error
	}{
		{"ImportKey", func(c *Client) error {
			_, err := c.ImportKey(context.Background(), vslotID, KeyData{})
			return err
		}},
		{"ImportKeyValues", func(c *Client) error {
			_, err := c.ImportKeyValues(context.Background(), keyID, nil)
			return err
		}},
		{"AttachKey", func(c *Client) error {
			_, err := c.AttachKey(context.Background(), vslotID, KeyData{})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusKeyAttributesDifferent)
				json.NewEncoder(w).Encode(map[string]string{
					"code":    ErrCodeInternalKeyAttributesDiffer,
					"message": "internal key attributes differ from the external key",
				})
			})

			err := tc.call(client)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want *APIError", err)
			}
			if apiErr.StatusCode != 260 || apiErr.Code != ErrCodeInternalKeyAttributesDiffer {
				t.Errorf("got StatusCode=%d Code=%q, want 260 INTERNAL_KEY_ATTRIBUTES_DIFFERENT", apiErr.StatusCode, apiErr.Code)
			}
		})
	}
}

func TestClient_DeriveKey(t *testing.T) {
	keyID := uuid.New()
	derivedID := uuid.New()

	t.Run("kcv", func(t *testing.T) {
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			wantPath := "/api/keys/" + keyID.String() + "/p/derive"
			if r.URL.Path != wantPath {
				t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
			}
			if got, want := r.Header.Get("Content-Type"), "application/kms.derive+json"; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decoding request body: %v", err)
			}
			if len(req) != 2 || req["algorithm"] != "DERIVE_KCV" || req["persistence"] != "NONE" {
				t.Errorf("request body = %v, want exactly algorithm=DERIVE_KCV persistence=NONE", req)
			}
			json.NewEncoder(w).Encode(KeyDataResponse{
				Values: []KeyValue{{Type: KeyValueTypeRaw, Value: []byte{0xC0, 0xFE}}},
			})
		})

		got, err := client.DeriveKey(context.Background(), keyID, DeriveRequest{
			Algorithm:   "DERIVE_KCV",
			Persistence: PersistenceNone,
		})
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}
		if len(got.Values) != 1 || !bytes.Equal(got.Values[0].Value, []byte{0xC0, 0xFE}) {
			t.Errorf("derived values not surfaced: %+v", got.Values)
		}
	})

	t.Run("aes cbc", func(t *testing.T) {
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decoding request body: %v", err)
			}
			if req["algorithm"] != "DERIVE_AES_CBC" || req["keyAlgorithm"] != "AES128" || req["persistence"] != "INTERNAL" {
				t.Errorf("request body = %v", req)
			}
			// DeriveDataModel attributes are string-valued on the wire.
			attrs, _ := req["attributes"].(map[string]any)
			if _, ok := attrs["label"].(string); !ok {
				t.Errorf("attributes.label = %v, want a string", attrs["label"])
			}
			if _, ok := attrs["iv"].(string); !ok {
				t.Errorf("attributes.iv = %v, want a base64 string", attrs["iv"])
			}
			json.NewEncoder(w).Encode(KeyDataResponse{ID: derivedID})
		})

		got, err := client.DeriveKey(context.Background(), keyID, DeriveRequest{
			Algorithm:    "DERIVE_AES_CBC",
			KeyAlgorithm: "AES128",
			Persistence:  PersistenceInternal,
			Attributes: map[string]string{
				"label": "derived-key",
				"data":  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32)),
				"iv":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 16)),
			},
		})
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}
		if got.ID != derivedID {
			t.Errorf("ID = %s, want %s", got.ID, derivedID)
		}
	})
}

func TestClient_TransportKey(t *testing.T) {
	keyID := uuid.New()
	targetVslotID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/keys/" + keyID.String() + "/transport"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.transport+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if len(req) != 1 || req["vslotId"] != targetVslotID.String() {
			t.Errorf("request body = %v, want exactly vslotId=%s", req, targetVslotID)
		}
		json.NewEncoder(w).Encode(KeyDataResponse{ID: keyID})
	})

	got, err := client.TransportKey(context.Background(), keyID, targetVslotID)
	if err != nil {
		t.Fatalf("TransportKey: %v", err)
	}
	if got.ID != keyID {
		t.Errorf("ID = %s, want %s", got.ID, keyID)
	}
}
