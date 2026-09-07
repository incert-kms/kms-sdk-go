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

func TestClient_GenerateCertificate(t *testing.T) {
	keyID := uuid.New()
	issuerKeyID := uuid.New()
	der := []byte{0x30, 0x82, 0x01}

	cases := []struct {
		name    string
		request CertificateRequest
		check   func(t *testing.T, req map[string]any)
	}{
		{
			name:    "self-signed",
			request: CertificateRequest{CommonName: "test", OrganisationUnit: "IT", SignatureAlgorithm: "EC_SHA256"},
			check: func(t *testing.T, req map[string]any) {
				// The organisation fields use the British wire spelling.
				if req["organisationUnit"] != "IT" {
					t.Errorf("organisationUnit = %v, want IT", req["organisationUnit"])
				}
				if _, ok := req["issuerKeyId"]; ok {
					t.Error("issuerKeyId must be omitted for a self-signed certificate")
				}
				if _, ok := req["encoded"]; ok {
					t.Error("encoded must be omitted on certgen")
				}
			},
		},
		{
			name: "issued via CA-backed key",
			request: CertificateRequest{
				CommonName:  "test",
				IssuerKeyID: issuerKeyID,
				IssuerAttributes: map[string]any{
					"EndEntityName":          "coco-jambo",
					"EndEntityProfileName":   "EMPTY",
					"CertificateProfileName": "ENDUSER",
				},
			},
			check: func(t *testing.T, req map[string]any) {
				if req["issuerKeyId"] != issuerKeyID.String() {
					t.Errorf("issuerKeyId = %v, want %s", req["issuerKeyId"], issuerKeyID)
				}
				attrs, _ := req["issuerAttributes"].(map[string]any)
				if attrs["EndEntityProfileName"] != "EMPTY" {
					t.Errorf("issuerAttributes = %v", attrs)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				wantPath := "/api/keys/" + keyID.String() + "/p/certgen"
				if r.URL.Path != wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
				}
				if got, want := r.Header.Get("Content-Type"), "application/kms.certificate+json"; got != want {
					t.Errorf("Content-Type = %q, want %q", got, want)
				}
				var req map[string]any
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decoding request body: %v", err)
				}
				if req["commonName"] != "test" {
					t.Errorf("commonName = %v, want test", req["commonName"])
				}
				tc.check(t, req)
				json.NewEncoder(w).Encode(struct {
					Data []byte `json:"data"`
				}{Data: der})
			})

			got, err := client.GenerateCertificate(context.Background(), keyID, tc.request)
			if err != nil {
				t.Fatalf("GenerateCertificate: %v", err)
			}
			if !bytes.Equal(got, der) {
				t.Errorf("got %x, want %x", got, der)
			}
		})
	}
}

func TestClient_GenerateCSR(t *testing.T) {
	keyID := uuid.New()
	csr := []byte{0x30, 0x81, 0x02}
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/keys/" + keyID.String() + "/p/csrgen"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if got, want := r.Header.Get("Content-Type"), "application/kms.certificate+json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if req["commonName"] != "test" || req["challenge"] != "ch4llenge" || req["unstructuredName"] != "example" {
			t.Errorf("request body = %v", req)
		}
		if req["signatureAlgorithm"] != "EC_SHA256" {
			t.Errorf("signatureAlgorithm = %v, want EC_SHA256", req["signatureAlgorithm"])
		}
		json.NewEncoder(w).Encode(struct {
			Data []byte `json:"data"`
		}{Data: csr})
	})

	got, err := client.GenerateCSR(context.Background(), keyID, CertificateRequest{
		CommonName:         "test",
		Challenge:          "ch4llenge",
		UnstructuredName:   "example",
		SignatureAlgorithm: "EC_SHA256",
	})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if !bytes.Equal(got, csr) {
		t.Errorf("got %x, want %x", got, csr)
	}
}

func TestClient_UpdateCertificate(t *testing.T) {
	keyID := uuid.New()
	certificate := []byte{0x30, 0x82, 0x03}

	cases := []struct {
		name      string
		storeInDB bool
		wantKeys  int
	}{
		{"default storage", false, 1},
		{"store in db", true, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				wantPath := "/api/keys/" + keyID.String() + "/p/certupdate"
				if r.URL.Path != wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
				}
				if got, want := r.Header.Get("Content-Type"), "application/kms.certificate+json"; got != want {
					t.Errorf("Content-Type = %q, want %q", got, want)
				}
				var req map[string]any
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decoding request body: %v", err)
				}
				if req["encoded"] != base64.StdEncoding.EncodeToString(certificate) {
					t.Errorf("encoded = %v, want the base64 certificate", req["encoded"])
				}
				if len(req) != tc.wantKeys {
					t.Errorf("request body = %v, want %d keys", req, tc.wantKeys)
				}
				if tc.storeInDB && req["storeInDb"] != true {
					t.Errorf("storeInDb = %v, want true", req["storeInDb"])
				}
				json.NewEncoder(w).Encode(struct {
					Data []byte `json:"data"`
				}{Data: certificate})
			})

			got, err := client.UpdateCertificate(context.Background(), keyID, certificate, tc.storeInDB)
			if err != nil {
				t.Fatalf("UpdateCertificate: %v", err)
			}
			if !bytes.Equal(got, certificate) {
				t.Errorf("got %x, want %x", got, certificate)
			}
		})
	}
}
