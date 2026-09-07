package kmssdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// SignSOD signs an ICAO Document Security Object with the given key and
// returns the assembled, encoded SOD (SignatureDataResponseModel). It shares
// the sign endpoint with [Client.Sign] but uses its own media type and request
// schema.
func (c *Client) SignSOD(ctx context.Context, keyID uuid.UUID, request SignSODRequest) ([]byte, error) {
	var result struct {
		Data []byte `json:"data"`
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling sod sign request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/sign", body, true, &result, "application/kms.sign-sod+json"); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// SignTimestamp produces an RFC 3161 timestamp response (DER TimeStampResp)
// signed by the given key (SignatureDataResponseModel). The key must carry a
// certificate; deployment configuration constrains accepted policies and
// extensions.
func (c *Client) SignTimestamp(ctx context.Context, keyID uuid.UUID, request SignTimestampRequest) ([]byte, error) {
	var result struct {
		Data []byte `json:"data"`
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling timestamp sign request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/sign", body, true, &result, "application/kms.sign-timestamp+json"); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// SignPDF signs a PDF document with the given key and returns the signed PDF
// bytes. The request body is a plain data envelope carrying the PDF; the
// operation is deployment-documented and absent from some API exports.
func (c *Client) SignPDF(ctx context.Context, keyID uuid.UUID, pdf []byte) ([]byte, error) {
	var result struct {
		Data []byte `json:"data"`
	}

	body, err := json.Marshal(struct {
		Data []byte `json:"data"`
	}{Data: pdf})
	if err != nil {
		return nil, fmt.Errorf("marshaling pdf sign request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/sign", body, true, &result, "application/kms.sign+pdf"); err != nil {
		return nil, err
	}
	return result.Data, nil
}
