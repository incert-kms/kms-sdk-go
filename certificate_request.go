package kmssdk

import (
	"time"

	"github.com/google/uuid"
)

// CertificateRequest is the request body of the certificate operations on a
// key (CertificateDataModel). [Client.GenerateCertificate] uses the
// subject-DN, validity, serial and issuer fields (self-signed when
// IssuerKeyID is empty); [Client.GenerateCSR] additionally honors Challenge
// and UnstructuredName; [Client.UpdateCertificate] builds its own request
// from Encoded and StoreInDB. Field names and JSON tags follow the server's
// British spellings.
type CertificateRequest struct {
	CommonName       string `json:"commonName,omitempty"`
	OrganisationUnit string `json:"organisationUnit,omitempty"`
	OrganisationName string `json:"organisationName,omitempty"`
	LocalityName     string `json:"localityName,omitempty"`
	StateName        string `json:"stateName,omitempty"`
	CountryCode      string `json:"countryCode,omitempty"` // ISO 3166-1 alpha-2, e.g. "LU"
	EmailAddress     string `json:"emailAddress,omitempty"`
	// IssuerKeyID selects an issuer key whose crypto provider is a CA;
	// IssuerAttributes carries the CA coordinates the provider needs (e.g.
	// EJBCA end-entity and profile names).
	IssuerKeyID        uuid.UUID      `json:"issuerKeyId,omitzero"`
	IssuerAttributes   map[string]any `json:"issuerAttributes,omitempty"`
	SignatureAlgorithm string         `json:"signatureAlgorithm,omitempty"`
	ValidFrom          time.Time      `json:"validFrom,omitzero"`
	ValidTo            time.Time      `json:"validTo,omitzero"`
	SerialNumber       *int           `json:"serialNumber,omitempty"`
	Challenge          string         `json:"challenge,omitempty"`
	UnstructuredName   string         `json:"unstructuredName,omitempty"`
	// Encoded is the X.509 certificate (DER) uploaded by a certificate
	// update.
	Encoded []byte `json:"encoded,omitempty"`
	// StoreInDB additionally stores the certificate in the KMS database
	// regardless of the key's persistence (servers >= 4.3.2.1; meaningful for
	// INTERNAL keys only, whose certificates otherwise live in the provider).
	StoreInDB bool   `json:"storeInDb,omitempty"`
	Data      []byte `json:"data,omitempty"`
}
