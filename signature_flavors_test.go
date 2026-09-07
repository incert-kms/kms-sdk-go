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

func TestClient_SignSOD(t *testing.T) {
	keyID := uuid.New()
	dgHash := []byte{0x3D, 0xA4, 0x07}
	sod := []byte{0x30, 0x82}
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/keys/" + keyID.String() + "/p/sign"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.sign-sod+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if req["algorithm"] != "RSA_PKCS_SHA1" || req["digestAlgorithm"] != "SHA256" {
			t.Errorf("request body = %v, want algorithm/digestAlgorithm set", req)
		}
		if req["ldsVersion"] != "1.8" {
			t.Errorf("ldsVersion = %v, want 1.8", req["ldsVersion"])
		}
		// The DG hash fields are flat, lowercase dgNhash keys.
		wantHash := base64.StdEncoding.EncodeToString(dgHash)
		if req["dg1hash"] != wantHash || req["dg2hash"] != wantHash {
			t.Errorf("dg1hash/dg2hash = %v/%v, want %q", req["dg1hash"], req["dg2hash"], wantHash)
		}
		if _, ok := req["dg3hash"]; ok {
			t.Error("unset DG hashes must be omitted")
		}
		if len(req) != 5 {
			t.Errorf("request body keys = %v, want exactly 5", req)
		}
		json.NewEncoder(w).Encode(struct {
			Data []byte `json:"data"`
		}{Data: sod})
	})

	got, err := client.SignSOD(context.Background(), keyID, SignSODRequest{
		Algorithm:       "RSA_PKCS_SHA1",
		DigestAlgorithm: "SHA256",
		LDSVersion:      "1.8",
		DG1Hash:         dgHash,
		DG2Hash:         dgHash,
	})
	if err != nil {
		t.Fatalf("SignSOD: %v", err)
	}
	if !bytes.Equal(got, sod) {
		t.Errorf("got %x, want %x", got, sod)
	}
}

func TestClient_SignTimestamp(t *testing.T) {
	keyID := uuid.New()
	tsr := []byte{0x30, 0x81}

	cases := []struct {
		name    string
		request SignTimestampRequest
		check   func(t *testing.T, req map[string]any)
	}{
		{
			name:    "complete tsq",
			request: SignTimestampRequest{Algorithm: "EC_SHA256", TSQ: []byte{0x01, 0x02}},
			check: func(t *testing.T, req map[string]any) {
				if req["tsq"] != base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}) {
					t.Errorf("tsq = %v", req["tsq"])
				}
				if _, ok := req["digest"]; ok {
					t.Error("digest must be omitted when tsq is set")
				}
				if len(req) != 2 {
					t.Errorf("request body keys = %v, want exactly algorithm and tsq", req)
				}
			},
		},
		{
			name: "digest and digest algorithm",
			request: SignTimestampRequest{
				Algorithm:       "EC_SHA256",
				Digest:          []byte{0xEE, 0x9A},
				DigestAlgorithm: "SHA256",
			},
			check: func(t *testing.T, req map[string]any) {
				if req["digest"] != base64.StdEncoding.EncodeToString([]byte{0xEE, 0x9A}) {
					t.Errorf("digest = %v", req["digest"])
				}
				if req["digestAlgorithm"] != "SHA256" {
					t.Errorf("digestAlgorithm = %v, want SHA256", req["digestAlgorithm"])
				}
				if _, ok := req["tsq"]; ok {
					t.Error("tsq must be omitted when digest is used")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				wantPath := "/api/keys/" + keyID.String() + "/p/sign"
				if r.URL.Path != wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
				}
				if got, want := r.Header.Get("Content-Type"), "application/kms.sign-timestamp+json"; got != want {
					t.Errorf("Content-Type = %q, want %q", got, want)
				}
				var req map[string]any
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decoding request body: %v", err)
				}
				if req["algorithm"] != "EC_SHA256" {
					t.Errorf("algorithm = %v, want EC_SHA256", req["algorithm"])
				}
				tc.check(t, req)
				json.NewEncoder(w).Encode(struct {
					Data []byte `json:"data"`
				}{Data: tsr})
			})

			got, err := client.SignTimestamp(context.Background(), keyID, tc.request)
			if err != nil {
				t.Fatalf("SignTimestamp: %v", err)
			}
			if !bytes.Equal(got, tsr) {
				t.Errorf("got %x, want %x", got, tsr)
			}
		})
	}
}

func TestClient_SignPDF(t *testing.T) {
	keyID := uuid.New()
	pdf := []byte("%PDF-1.7 test")
	signed := []byte("%PDF-1.7 signed")
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/keys/" + keyID.String() + "/p/sign"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.sign+pdf"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if len(req) != 1 || req["data"] != base64.StdEncoding.EncodeToString(pdf) {
			t.Errorf("request body = %v, want exactly the base64 PDF in data", req)
		}
		json.NewEncoder(w).Encode(struct {
			Data []byte `json:"data"`
		}{Data: signed})
	})

	got, err := client.SignPDF(context.Background(), keyID, pdf)
	if err != nil {
		t.Fatalf("SignPDF: %v", err)
	}
	if !bytes.Equal(got, signed) {
		t.Errorf("got %q, want %q", got, signed)
	}
}
