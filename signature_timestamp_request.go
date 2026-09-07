package kmssdk

// SignTimestampRequest is the request body of an RFC 3161 timestamp signature
// (SignatureTimestampDataModel). Provide either a complete DER TimeStampReq in
// TSQ, or Digest plus DigestAlgorithm (accepted: MD5, SHA1, SHA224, SHA256,
// SHA384, SHA512); when TSQ is set, the digest fields are ignored. Algorithm
// is a sign identifier supported by the key (e.g. "EC_SHA256"), and the
// signing key must carry a certificate.
type SignTimestampRequest struct {
	Algorithm       string `json:"algorithm"`
	TSQ             []byte `json:"tsq,omitempty"`
	Digest          []byte `json:"digest,omitempty"`
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
	Data            []byte `json:"data,omitempty"`
}
