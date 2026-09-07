package kmssdk

import (
	"time"

	"github.com/google/uuid"
)

// KeyAlias is a stable UUID handle that can be re-pointed from one key to
// another, e.g. across rotations (AliasKeySearchResultModel).
type KeyAlias struct {
	ID           uuid.UUID `json:"id,omitzero"`
	KeyID        uuid.UUID `json:"key,omitzero"` // the wire field is "key"
	Universe     string    `json:"universe,omitempty"`
	CreationDate time.Time `json:"creationDate,omitzero"`
	CreatedBy    string    `json:"createdBy,omitempty"`
}

// KeyAliasFilter narrows a [Client.FindKeyAliases] search. Zero-valued fields
// are ignored.
type KeyAliasFilter struct {
	ID    uuid.UUID // the alias id itself
	KeyID uuid.UUID // the key the alias currently points to
}
