package kmssdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// ErrSuccessorUnknown reports that a rotation succeeded but the successor key
// could not be identified from the rotated key's key links; re-query the key
// or use an alias to reach the current generation.
var ErrSuccessorUnknown = errors.New("key rotated but successor not identified")

// SetKeyState advances the lifecycle state of a key and/or toggles its enabled
// flag (KeyStateModel). The lifecycle is strictly forward-only (PROVISIONED →
// ACTIVE → DEACTIVATED → DESTROYED → DELETED); an illegal transition fails
// with [ErrCodeKeyLifecycle] (HTTP 500). To toggle enabled within the current
// state, pass the current state unchanged.
func (c *Client) SetKeyState(ctx context.Context, keyID uuid.UUID, state string, enabled bool) error {
	body, err := json.Marshal(KeyState{State: state, Enabled: enabled})
	if err != nil {
		return fmt.Errorf("marshaling state request: %w", err)
	}
	return c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/state", body, true, nil)
}

// RotateKey deactivates the key and creates a linked successor, returning the
// successor's id. The rotate endpoint itself returns an empty response, so the
// successor is discovered by comparing the key's key links before and after
// the rotation (KeyModel). When the rotation succeeded but no single new link
// appeared, the returned error matches [ErrSuccessorUnknown] — the rotation
// itself has still happened.
func (c *Client) RotateKey(ctx context.Context, keyID uuid.UUID) (uuid.UUID, error) {
	before, err := c.GetKey(ctx, keyID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("reading key before rotation: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/rotate", nil, true, nil); err != nil {
		return uuid.Nil, err
	}

	after, err := c.GetKey(ctx, keyID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("reading key after rotation: %w (%w)", err, ErrSuccessorUnknown)
	}

	successor, ok := newKeyLink(before.KeyLinks, after.KeyLinks, keyID)
	if !ok {
		return uuid.Nil, ErrSuccessorUnknown
	}
	return successor, nil
}

// newKeyLink returns the single entry of after that is neither in before nor
// self; ok is false when there is no such entry or more than one.
func newKeyLink(before, after []uuid.UUID, self uuid.UUID) (uuid.UUID, bool) {
	seen := make(map[uuid.UUID]bool, len(before)+1)
	seen[self] = true
	for _, id := range before {
		seen[id] = true
	}

	var successor uuid.UUID
	var count int
	for _, id := range after {
		if seen[id] {
			continue
		}
		seen[id] = true
		successor = id
		count++
	}
	return successor, count == 1
}

// FindKeyAliases lists the key aliases matching the filter, iterating server
// pages transparently (AliasKeySearchResultModel). Zero-valued filter fields
// are ignored.
func (c *Client) FindKeyAliases(ctx context.Context, filter KeyAliasFilter) ([]KeyAlias, error) {
	query := url.Values{}
	query.Set("sort", "creationDate,desc")
	if filter.ID != uuid.Nil {
		query.Set("id", filter.ID.String())
	}
	if filter.KeyID != uuid.Nil {
		query.Set("key.id", filter.KeyID.String())
	}

	return fetchAllPages[KeyAlias](ctx, c, "/keys/aliases", query)
}

// CreateKeyAlias creates a new alias pointing at the given key and returns it
// (AliasKeySearchResultModel). Re-point an existing alias with
// [Client.MoveKeyAlias].
func (c *Client) CreateKeyAlias(ctx context.Context, keyID uuid.UUID) (KeyAlias, error) {
	var result KeyAlias
	if err := c.do(ctx, http.MethodPost, "/keys/"+keyID.String()+"/alias", nil, true, &result); err != nil {
		return KeyAlias{}, err
	}
	return result, nil
}

// MoveKeyAlias re-points an existing alias from one key to another
// (AliasKeyModel): fromKeyID is the key the alias currently references,
// toKeyID the new target. It returns the updated alias.
func (c *Client) MoveKeyAlias(ctx context.Context, aliasID, fromKeyID, toKeyID uuid.UUID) (KeyAlias, error) {
	var result KeyAlias

	body, err := json.Marshal(struct {
		AliasID uuid.UUID `json:"aliasId"`
		KeyID   uuid.UUID `json:"keyId"`
	}{AliasID: aliasID, KeyID: fromKeyID})
	if err != nil {
		return KeyAlias{}, fmt.Errorf("marshaling alias request: %w", err)
	}

	if err := c.do(ctx, http.MethodPost, "/keys/"+toKeyID.String()+"/alias", body, true, &result); err != nil {
		return KeyAlias{}, err
	}
	return result, nil
}
