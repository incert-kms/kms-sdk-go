package kmssdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestClient_Sign(t *testing.T) {
	keyID := uuid.New()
	data := []byte("message to sign")
	signature := []byte{0xAA, 0xBB, 0xCC}
	salt := 32
	hashAlg := 592 // CKM_SHA256
	mgf := 2       // CKG_MGF1_SHA256

	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if want := "/api/keys/" + keyID.String() + "/p/sign"; r.URL.Path != want {
			t.Errorf("path = %s, want %s", r.URL.Path, want)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.sign+json"; got != want {
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
		if !bytes.Equal(req.Data, data) {
			t.Errorf("request Data = %x, want %x", req.Data, data)
		}
		if req.Algorithm != "RSA_PKCS-PSS_RAW" {
			t.Errorf("Algorithm = %q, want RSA_PKCS-PSS_RAW", req.Algorithm)
		}
		if got := req.Attributes["hashAlg"]; got != float64(hashAlg) {
			t.Errorf("Attributes.hashAlg = %v, want %d", got, hashAlg)
		}
		if got := req.Attributes["mgf"]; got != float64(mgf) {
			t.Errorf("Attributes.mgf = %v, want %d", got, mgf)
		}
		if got := req.Attributes["saltLength"]; got != float64(salt) {
			t.Errorf("Attributes.saltLength = %v, want %d", got, salt)
		}
		if _, present := req.Attributes["signature"]; present {
			t.Error("sign request must not carry a signature attribute")
		}
		json.NewEncoder(w).Encode(struct {
			Data []byte `json:"data"`
		}{Data: signature})
	})

	got, err := client.Sign(context.Background(), keyID, SignRequest{
		Data:      data,
		Algorithm: "RSA_PKCS-PSS_RAW",
		Attributes: &SignatureAttributes{
			HashAlg:    &hashAlg,
			MGF:        &mgf,
			SaltLength: &salt,
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(got, signature) {
		t.Errorf("signature = %x, want %x", got, signature)
	}
}

func TestClient_Verify(t *testing.T) {
	keyID := uuid.New()
	data := []byte("signed message")
	signature := []byte{0x01, 0x02, 0x03}

	for _, valid := range []bool{true, false} {
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			if want := "/api/keys/" + keyID.String() + "/p/verify"; r.URL.Path != want {
				t.Errorf("path = %s, want %s", r.URL.Path, want)
			}
			if got, want := r.Header.Get("Content-Type"), "application/kms.sign+json"; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}
			var req struct {
				Algorithm  string         `json:"algorithm"`
				Attributes map[string]any `json:"attributes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decoding request body: %v", err)
			}
			if req.Algorithm != "EC_SHA256" {
				t.Errorf("Algorithm = %q, want EC_SHA256", req.Algorithm)
			}
			if got, want := req.Attributes["signature"], base64.StdEncoding.EncodeToString(signature); got != want {
				t.Errorf("Attributes.signature = %v, want %q", got, want)
			}
			json.NewEncoder(w).Encode(struct {
				Valid bool `json:"valid"`
			}{Valid: valid})
		})

		got, err := client.Verify(context.Background(), keyID, SignRequest{
			Data:       data,
			Algorithm:  "EC_SHA256",
			Attributes: &SignatureAttributes{Signature: signature},
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got != valid {
			t.Errorf("valid = %v, want %v", got, valid)
		}
	}
}
