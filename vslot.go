package kmssdk

import (
	"time"

	"github.com/google/uuid"
)

type Vslot struct {
	ID           uuid.UUID  `json:"id"`
	Provider     uuid.UUID  `json:"provider"`
	ProviderName string     `json:"providerName"`
	LogLevelID   *uuid.UUID `json:"logLevelId"`
	Universe     string     `json:"universe"`
	CreationDate time.Time  `json:"creationDate"`
	CreatedBy    string     `json:"createdBy"`
}

type pagedResponse[T any] struct {
	Content       []T  `json:"content"`
	TotalPages    int  `json:"totalPages"`
	TotalElements int  `json:"totalElements"`
	Last          bool `json:"last"`
	First         bool `json:"first"`
}
