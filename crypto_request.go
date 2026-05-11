package kmssdk

type CryptoOperation string

const (
	OperationEncrypt CryptoOperation = "encrypt"
	OperationDecrypt CryptoOperation = "decrypt"
)

type CryptoRequest struct {
	Data       []byte     `json:"data"`
	Algorithm  string     `json:"algorithm"`
	Attributes Attributes `json:"attributes"`
}

type Attributes struct {
	IV []byte `json:"iv,omitempty"`
}
