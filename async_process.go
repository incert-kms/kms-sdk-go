package kmssdk

import (
	"time"

	"github.com/google/uuid"
)

// Async process statuses ([AsyncProcess.Status]).
const (
	AsyncProcessInProgress = "IN_PROGRESS"
	AsyncProcessFinished   = "FINISHED"
	AsyncProcessError      = "ERROR"
)

// AsyncProcess is the tracking record of a plugin operation executed
// asynchronously (AsyncKeyProcessModel / AsyncVslotProcessModel). Exactly one
// of KeyID and VslotID is set, matching the endpoint family the record came
// from. List results omit the ProcessJSON* fields; fetch a single process to
// see them. Finished records are retained for a deployment-configured period
// (24 hours by default), so poll promptly.
type AsyncProcess struct {
	ID      uuid.UUID `json:"id,omitzero"`
	Status  string    `json:"status,omitempty"`
	KeyID   uuid.UUID `json:"keyId,omitzero"`
	VslotID uuid.UUID `json:"vslotId,omitzero"`
	// Process names the operation the record tracks, e.g. "encrypt".
	Process string `json:"process,omitempty"`
	// ProcessJSONRequest and ProcessJSONResponse carry the operation's JSON
	// request and response bodies as strings; the response is present once
	// Status is FINISHED, unless it was stored on file storage
	// (ProcessResponseEmbeddedInDB false).
	ProcessJSONRequest          string    `json:"processJsonRequest,omitempty"`
	ProcessJSONResponse         string    `json:"processJsonResponse,omitempty"`
	DataFileName                string    `json:"dataFileName,omitempty"`
	DataEmbeddedInDB            bool      `json:"dataEmbeddedInDb,omitempty"`
	ProcessResponseEmbeddedInDB bool      `json:"processResponseEmbeddedInDb,omitempty"`
	CreatedBy                   string    `json:"createdBy,omitempty"`
	CreationDate                time.Time `json:"creationDate,omitzero"`
	StartDate                   time.Time `json:"startDate,omitzero"`
	EndDate                     time.Time `json:"endDate,omitzero"`
	Failures                    int       `json:"failures,omitempty"`
	// LastFailureReason is reset when the process is restarted.
	LastFailureReason string `json:"lastFailureReason,omitempty"`
}
