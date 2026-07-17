package kmssdk

// SignRequest is the request body of a sign or verify operation
// (SignatureDataModel). Data carries the payload — or, for the *_RAW
// algorithms, the caller-prepared digest; Algorithm is an identifier from the
// key's SupportedAlgorithms (e.g. "RSA_PKCS_SHA256", "EC_SHA256",
// "HMAC_SHA256", "AES_CMAC", "RSA_PKCS-PSS_RAW").
type SignRequest struct {
	Data       []byte               `json:"data"`
	Algorithm  string               `json:"algorithm"`
	Attributes *SignatureAttributes `json:"attributes,omitempty"`
}

// SignatureAttributes carries the algorithm-specific signature parameters.
// Verify puts the signature to check in Signature; RSA-PSS over a
// caller-prepared digest (RSA_PKCS-PSS_RAW) uses HashAlg/MGF/SaltLength with
// numeric PKCS#11 codes (e.g. HashAlg 592 = CKM_SHA256, MGF 2 =
// CKG_MGF1_SHA256), per 05-crypto-operations.md.
type SignatureAttributes struct {
	Signature  []byte `json:"signature,omitempty"`
	HashAlg    *int   `json:"hashAlg,omitempty"`
	MGF        *int   `json:"mgf,omitempty"`
	SaltLength *int   `json:"saltLength,omitempty"`
}
