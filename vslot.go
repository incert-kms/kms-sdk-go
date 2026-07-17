package kmssdk

import (
	"time"

	"github.com/google/uuid"
)

// Vslot is a virtual slot: the container in which keys live, bound to one
// crypto provider and one universe (VSlotSearchResultModel).
type Vslot struct {
	ID           uuid.UUID  `json:"id"`
	Provider     uuid.UUID  `json:"provider"`
	ProviderName string     `json:"providerName"`
	LogLevelID   *uuid.UUID `json:"logLevelId"`
	Universe     string     `json:"universe"`
	CreationDate time.Time  `json:"creationDate"`
	CreatedBy    string     `json:"createdBy"`
}

// pagedResponse is the Spring-style page envelope shared by all list
// endpoints.
type pagedResponse[T any] struct {
	Content       []T  `json:"content"`
	TotalPages    int  `json:"totalPages"`
	TotalElements int  `json:"totalElements"`
	Last          bool `json:"last"`
	First         bool `json:"first"`
}
