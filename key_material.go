package kmssdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// ExportKey exports key values in the formats described by values — each
// entry names the requested Type and Format, plus WrapKey or WrapKeyID for
// the wrapped formats (KeyDataModel). Public values may leave in clear
// formats; secret and private values only wrapped, and only when the key is
// extractable. The exported material is carried in the response Values.
func (c *Client) ExportKey(ctx context.Context, keyID uuid.UUID, values []KeyValue) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(KeyData{Values: values})
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling export request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/export", body, true, &result, "application/kms.key+json"); err != nil {
		return KeyDataResponse{}, err
	}
	return result, nil
}

// EditKey applies the given use-attribute flags to the key through the
// provider plugin (KeyDataModel — the server processes only useAttributes).
// Unlike a metadata-only update, the change propagates into the crypto
// provider; for INTERNAL keys some transitions are one-way (providers
// commonly forbid flipping extractable back to true) and fail with
// [ErrCodeBadRequest]. All eight flags are always sent.
func (c *Client) EditKey(ctx context.Context, keyID uuid.UUID, useAttributes KeyUseAttributes) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(KeyData{UseAttributes: &useAttributes})
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling edit request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/edit", body, true, &result, "application/kms.key+json"); err != nil {
		return KeyDataResponse{}, err
	}
	return result, nil
}

// ImportKey imports caller-supplied key material as a new key in the given
// vslot (KeyDataModel): the material travels in key.Values, plain or wrapped.
// An HTTP 260 consistency warning — attributes of the imported material
// differ from the request — surfaces as an [APIError] with Code
// [ErrCodeInternalKeyAttributesDiffer]; the key may nonetheless have been
// created, so re-query to inspect it.
func (c *Client) ImportKey(ctx context.Context, vslotID uuid.UUID, key KeyData) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(key)
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling import request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/vslots/"+vslotID.String()+"/p/ki?async=false", body, true, &result, "application/kms.key+json"); err != nil {
		return KeyDataResponse{}, err
	}
	return result, nil
}

// ImportKeyValues imports material into an existing key — filling an empty
// IMPORTED shell, or replacing a value referenced by its [KeyValue.ID]
// (KeyDataModel). HTTP 260 is reported as for [Client.ImportKey].
func (c *Client) ImportKeyValues(ctx context.Context, keyID uuid.UUID, values []KeyValue) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(KeyData{Values: values})
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling import request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/ki", body, true, &result, "application/kms.key+json"); err != nil {
		return KeyDataResponse{}, err
	}
	return result, nil
}

// AttachKey registers a key that already exists inside the vslot's crypto
// provider (KeyDataModel). The provider-side key is selected via
// key.Attributes; the attribute name is provider-dependent: "prov_id"
// (generic; for PKCS#11 the CKA_ID as a hex string), "hsm_id" (PKCS#11 HSMs)
// or "kms_id" (key UUID on a remote KMS). HTTP 260 is reported as for
// [Client.ImportKey].
func (c *Client) AttachKey(ctx context.Context, vslotID uuid.UUID, key KeyData) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(key)
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling attach request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/vslots/"+vslotID.String()+"/p/ka?async=false", body, true, &result, "application/kms.key+json"); err != nil {
		return KeyDataResponse{}, err
	}
	return result, nil
}

// DeriveKey derives a new key (or transient value) from an existing key and
// returns the derived key's id and, for persistence NONE, its values
// (KeyDataResponseModel). Derivation is gated by the base key's derive use
// attribute.
func (c *Client) DeriveKey(ctx context.Context, keyID uuid.UUID, request DeriveRequest) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(request)
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling derive request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/p/derive", body, true, &result, "application/kms.derive+json"); err != nil {
		return KeyDataResponse{}, err
	}
	return result, nil
}

// TransportKey copies the key into another vslot, re-wrapping it for the
// destination crypto provider (KeyTransportModel). Feasibility depends on the
// source and destination providers.
func (c *Client) TransportKey(ctx context.Context, keyID, targetVslotID uuid.UUID) (KeyDataResponse, error) {
	var result KeyDataResponse

	body, err := json.Marshal(struct {
		VslotID uuid.UUID `json:"vslotId"`
	}{VslotID: targetVslotID})
	if err != nil {
		return KeyDataResponse{}, fmt.Errorf("marshaling transport request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/transport", body, true, &result, "application/kms.transport+json"); err != nil {
		return KeyDataResponse{}, err
	}
	return result, nil
}
