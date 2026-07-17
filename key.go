package kmssdk

import (
	"time"

	"github.com/google/uuid"
)

// Key lifecycle states. The lifecycle is one-way: PROVISIONED → ACTIVE →
// DEACTIVATED → DESTROYED → DELETED; a key can never return to an earlier
// state. DELETED removes both the key material and its metadata immediately.
const (
	KeyStateProvisioned = "PROVISIONED"
	KeyStateActive      = "ACTIVE"
	KeyStateDeactivated = "DEACTIVATED"
	KeyStateDestroyed   = "DESTROYED"
	KeyStateDeleted     = "DELETED"
)

// Key persistence modes: where the key material lives.
const (
	PersistenceInternal = "INTERNAL" // material stored in the crypto provider (e.g. HSM)
	PersistenceExternal = "EXTERNAL" // material stored wrapped in the KMS database
	PersistenceNone     = "NONE"     // material returned to the caller and not stored
)

// Key types: how the key entered the system.
const (
	KeyTypeGenerated = "GENERATED"
	KeyTypeProvider  = "PROVIDER"
	KeyTypeImported  = "IMPORTED"
	KeyTypeWrap      = "WRAP"
)

// KeyState is the lifecycle state of a key as reported in search results
// (KeyStateModel).
type KeyState struct {
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
}

// KeyFilter narrows a [Client.FindKeys] search. Zero-valued fields are
// ignored.
type KeyFilter struct {
	Name string
	ID   uuid.UUID
}

// KeySearchResult is the list/search view of a key returned by
// [Client.FindKeys] and [Client.GetKeys] (KeySearchResultModel) — lighter than
// [KeyDetail].
type KeySearchResult struct {
	ID             uuid.UUID `json:"id,omitzero"`
	VslotID        uuid.UUID `json:"vslotId,omitzero"`
	Name           string    `json:"name,omitempty"`
	Alg            string    `json:"alg,omitempty"`
	AlgType        string    `json:"algType,omitempty"`
	Persistence    string    `json:"persistence,omitempty"`
	State          KeyState  `json:"state,omitzero"`
	IDProvider     []byte    `json:"idProvider,omitempty"`
	IDUser         []byte    `json:"idUser,omitempty"`
	KCV            []byte    `json:"kcv,omitempty"`
	ValidFrom      time.Time `json:"validFrom,omitzero"`
	ValidTo        time.Time `json:"validTo,omitzero"`
	CreationDate   time.Time `json:"creationDate,omitzero"`
	CreatedBy      string    `json:"createdBy,omitempty"`
	AttachedValues []string  `json:"attachedValues,omitempty"`
}

// KeyDetail is the full representation of a key returned by [Client.GetKey]
// (KeyModel). Consult SupportedAlgorithms for the operations and attribute
// parameters the key supports, and UseAttributes for what it is allowed to do.
type KeyDetail struct {
	ID                  uuid.UUID         `json:"id,omitzero"`
	AliasID             *uuid.UUID        `json:"aliasId,omitempty"`
	Type                string            `json:"type,omitempty"`
	UseAttributes       *KeyUseAttributes `json:"useAttributes,omitempty"`
	IDProvider          []byte            `json:"idProvider,omitempty"`
	IDUser              []byte            `json:"idUser,omitempty"`
	Name                string            `json:"name,omitempty"`
	VslotID             uuid.UUID         `json:"vslotId,omitzero"`
	Alg                 string            `json:"alg,omitempty"`
	KeySize             *int              `json:"keySize,omitempty"`
	Attributes          map[string]string `json:"attributes,omitempty"`
	AttributesP11       map[string]string `json:"attributesP11,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
	ValidFrom           time.Time         `json:"validFrom,omitzero"`
	ValidTo             time.Time         `json:"validTo,omitzero"`
	KeyValues           []KeyValue        `json:"keyValues,omitempty"`
	KeyLinks            []uuid.UUID       `json:"keyLinks,omitempty"`
	Rotated             bool              `json:"rotated,omitempty"`
	KCV                 []byte            `json:"kcv,omitempty"`
	Persistence         string            `json:"persistence,omitempty"`
	State               string            `json:"state,omitempty"`
	Enabled             bool              `json:"enabled,omitempty"`
	LogLevelID          *uuid.UUID        `json:"logLevelId,omitempty"`
	CreationDate        time.Time         `json:"creationDate,omitzero"`
	CreatedBy           string            `json:"createdBy,omitempty"`
	SupportedAlgorithms []CryptoAlgorithm `json:"supportedAlgorithms,omitempty"`
}

// KeyData is the request body for key generation via [Client.CreateKey]
// (KeyDataModel). For generation, Values is usually omitted; with
// Persistence == [PersistenceNone] it describes how the generated material
// should be returned (wrapped).
type KeyData struct {
	Name          string            `json:"name,omitempty"`
	Type          string            `json:"type,omitempty"`
	UseAttributes *KeyUseAttributes `json:"useAttributes,omitempty"`
	Alg           string            `json:"alg,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	AttributesP11 map[string]string `json:"attributesP11,omitempty"`
	ValidFrom     time.Time         `json:"validFrom,omitzero"`
	ValidTo       time.Time         `json:"validTo,omitzero"`
	Labels        map[string]string `json:"labels,omitempty"`
	LogLevelID    *uuid.UUID        `json:"logLevelId,omitempty"`
	Values        []KeyValue        `json:"values,omitempty"`
	Persistence   string            `json:"persistence,omitempty"`
	State         string            `json:"state,omitempty"`
	Data          []byte            `json:"data,omitempty"`
}

// KeyDataResponse is the result of a key creation (KeyDataResponseModel): the
// id of the new key and, when requested (persistence NONE), the exported
// values.
type KeyDataResponse struct {
	ID     uuid.UUID  `json:"id"`
	Values []KeyValue `json:"values,omitempty"`
}

// KeyUseAttributes are the PKCS#11-style usage flags of a key
// (KeyUseAttributesModel). Operations are rejected when the corresponding flag
// is off. When the struct is present in a request, all eight flags are
// serialized so that explicit false values reach the server.
type KeyUseAttributes struct {
	Extractable bool `json:"extractable"`
	Sign        bool `json:"sign"`
	Verify      bool `json:"verify"`
	Encrypt     bool `json:"encrypt"`
	Decrypt     bool `json:"decrypt"`
	Wrap        bool `json:"wrap"`
	Unwrap      bool `json:"unwrap"`
	Derive      bool `json:"derive"`
}

// KeyValue is the envelope for a single piece of key material
// (KeyValueModel), used both to carry material and to describe requested
// export formats and wrapping.
type KeyValue struct {
	ID                      uuid.UUID         `json:"id,omitzero"`
	Type                    string            `json:"type,omitempty"`
	Value                   []byte            `json:"value,omitempty"`
	Format                  string            `json:"format,omitempty"`
	FormatParameters        map[string]string `json:"formatParameters,omitempty"`
	Password                string            `json:"password,omitempty"`
	WrapKey                 []byte            `json:"wrapKey,omitempty"`
	WrapKeyFormat           string            `json:"wrapKeyFormat,omitempty"`
	WrapKeyFormatParameters map[string]string `json:"wrapKeyFormatParameters,omitempty"`
	WrapKeyID               *uuid.UUID        `json:"wrapKeyId,omitempty"`
	WrappingKey             *KeyDetail        `json:"wrappingKeyModel,omitempty"`
}

// CryptoAlgorithm describes one algorithm supported by a key
// (CryptoAlgorithmModel): the identifier to pass in operation requests, the
// key types and usages it applies to, and (via Params) the attribute keys it
// consumes, e.g. "iv".
type CryptoAlgorithm struct {
	Algorithm   string         `json:"algorithm,omitempty"`
	Description string         `json:"description,omitempty"`
	KeyTypes    []string       `json:"keyTypes,omitempty"`
	KeyUsage    []string       `json:"keyUsage,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
}
