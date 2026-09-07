package kmssdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// GenerateCertificate generates an X.509 certificate for the key — self-signed,
// or issued through IssuerKeyID/IssuerAttributes when the issuer key's crypto
// provider is a CA — and returns the DER-encoded certificate
// (CertificateResponseDataModel). Certificates apply to asymmetric keys; where
// the certificate is stored follows the key's persistence unless
// request.StoreInDB is set.
func (c *Client) GenerateCertificate(ctx context.Context, keyID uuid.UUID, request CertificateRequest) ([]byte, error) {
	return c.certificateOperation(ctx, keyID, "certgen", request)
}

// GenerateCSR generates a PKCS#10 certificate signing request for the key and
// returns it DER-encoded (CertificateResponseDataModel).
func (c *Client) GenerateCSR(ctx context.Context, keyID uuid.UUID, request CertificateRequest) ([]byte, error) {
	return c.certificateOperation(ctx, keyID, "csrgen", request)
}

// UpdateCertificate uploads a certificate (DER) for the key — typically the
// one received from a CA for a previously generated CSR (CertificateDataModel,
// fields encoded and storeInDb only). storeInDB additionally stores the
// certificate in the KMS database regardless of the key's persistence
// (servers >= 4.3.2.1; meaningful for INTERNAL keys only).
func (c *Client) UpdateCertificate(ctx context.Context, keyID uuid.UUID, certificate []byte, storeInDB bool) ([]byte, error) {
	return c.certificateOperation(ctx, keyID, "certupdate", CertificateRequest{Encoded: certificate, StoreInDB: storeInDB})
}

// certificateOperation posts one of the certificate plugin operations
// (certgen, csrgen, certupdate) and extracts the DER payload.
func (c *Client) certificateOperation(ctx context.Context, keyID uuid.UUID, op string, request CertificateRequest) ([]byte, error) {
	var result struct {
		Data []byte `json:"data"`
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling %s request: %w", op, err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/"+op, body, true, &result, "application/kms.certificate+json"); err != nil {
		return nil, err
	}
	return result.Data, nil
}
