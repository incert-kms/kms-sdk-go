package kmssdk

// CryptoOperation selects the cryptographic operation performed by
// [Client.Crypto].
type CryptoOperation string

// Supported crypto operations.
const (
	OperationEncrypt CryptoOperation = "encrypt"
	OperationDecrypt CryptoOperation = "decrypt"
)

// CryptoRequest is the request body of an encrypt/decrypt operation
// (EncryptDataModel). Data carries the plaintext (encrypt) or ciphertext
// (decrypt); Algorithm is an identifier from the key's SupportedAlgorithms
// (e.g. "AES_GCM", "AES_CBC_PKCS7", "RSA_OAEP_SHA512").
//
// Attributes carries the algorithm-specific parameters named by the key's
// [CryptoAlgorithm].Params, for example:
//
//	map[string]any{"iv": iv}                 // AES_CBC*, AES_GCM ([]byte encodes as base64)
//	map[string]any{"iv": nonce, "counter": 1} // AES_CTR
//	map[string]any{"iv": nonce, "aad": aad}   // AES_GCM with additional authenticated data
//	map[string]any{"label": label}            // RSA_OAEP_* (optional OAEP label)
type CryptoRequest struct {
	Data       []byte         `json:"data"`
	Algorithm  string         `json:"algorithm"`
	Attributes map[string]any `json:"attributes,omitempty"`
}
