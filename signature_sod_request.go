package kmssdk

// SignSODRequest is the request body of an ICAO Document Security Object
// signature (SignatureSodDataModel). Algorithm (a sign identifier supported by
// the key) and DigestAlgorithm (e.g. "SHA256" — correctness is the caller's
// responsibility) are required, and at least one data-group hash must be set.
// The server assembles and signs the SOD from the supplied hashes of ICAO Doc
// 9303 Data Groups 1–16.
type SignSODRequest struct {
	Algorithm       string `json:"algorithm"`
	DigestAlgorithm string `json:"digestAlgorithm"`
	LDSVersion      string `json:"ldsVersion,omitempty"`
	UnicodeVersion  string `json:"unicodeVersion,omitempty"`
	DG1Hash         []byte `json:"dg1hash,omitempty"`
	DG2Hash         []byte `json:"dg2hash,omitempty"`
	DG3Hash         []byte `json:"dg3hash,omitempty"`
	DG4Hash         []byte `json:"dg4hash,omitempty"`
	DG5Hash         []byte `json:"dg5hash,omitempty"`
	DG6Hash         []byte `json:"dg6hash,omitempty"`
	DG7Hash         []byte `json:"dg7hash,omitempty"`
	DG8Hash         []byte `json:"dg8hash,omitempty"`
	DG9Hash         []byte `json:"dg9hash,omitempty"`
	DG10Hash        []byte `json:"dg10hash,omitempty"`
	DG11Hash        []byte `json:"dg11hash,omitempty"`
	DG12Hash        []byte `json:"dg12hash,omitempty"`
	DG13Hash        []byte `json:"dg13hash,omitempty"`
	DG14Hash        []byte `json:"dg14hash,omitempty"`
	DG15Hash        []byte `json:"dg15hash,omitempty"`
	DG16Hash        []byte `json:"dg16hash,omitempty"`
	Data            []byte `json:"data,omitempty"`
}
