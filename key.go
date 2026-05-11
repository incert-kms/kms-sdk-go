package kmssdk

import (
	"time"

	"github.com/google/uuid"
)

type KeyState struct {
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
}

type KeyFilter struct {
	Name string
	ID   uuid.UUID
}

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

type KeyUseAttributes struct {
	Extractable bool `json:"extractable,omitempty"`
	Sign        bool `json:"sign,omitempty"`
	Verify      bool `json:"verify,omitempty"`
	Encrypt     bool `json:"encrypt,omitempty"`
	Decrypt     bool `json:"decrypt,omitempty"`
	Wrap        bool `json:"wrap,omitempty"`
	Unwrap      bool `json:"unwrap,omitempty"`
	Derive      bool `json:"derive,omitempty"`
}

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

type CryptoAlgorithm struct {
	Algorithm   string         `json:"algorithm,omitempty"`
	Description string         `json:"description,omitempty"`
	KeyTypes    []string       `json:"keyTypes,omitempty"`
	KeyUsage    []string       `json:"keyUsage,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
}
