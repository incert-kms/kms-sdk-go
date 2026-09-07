package kmssdk

// DeriveRequest is the request body of a key derivation (DeriveDataModel).
// Algorithm is a derivation identifier from the base key's supported
// algorithms (e.g. "DERIVE_SHA256", "DERIVE_AES_CBC", "DERIVE_KCV");
// KeyAlgorithm sets the algorithm of the derived key. Attributes carries
// string-valued parameters such as "label" (name of the derived key), "data"
// (base64 derivation input, required for the DERIVE_AES_* algorithms) and
// "iv" (DERIVE_AES_CBC) — unlike [CryptoRequest.Attributes], the wire model
// maps to strings, not arbitrary values. With Persistence ==
// [PersistenceNone], Values describes how the derived material is returned
// (e.g. wrapped).
type DeriveRequest struct {
	Algorithm    string            `json:"algorithm"`
	KeyAlgorithm string            `json:"keyAlgorithm,omitempty"`
	Persistence  string            `json:"persistence,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Values       []KeyValue        `json:"values,omitempty"`
	Data         []byte            `json:"data,omitempty"`
}
