package kmssdk

import (
	"context"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// GetKeyAsyncProcesses lists the async processes of key-scoped plugin
// operations, iterating server pages transparently
// (AsyncKeyProcessSearchResultModel).
func (c *Client) GetKeyAsyncProcesses(ctx context.Context) ([]AsyncProcess, error) {
	query := url.Values{}
	query.Set("sort", "creationDate,desc")
	return fetchAllPages[AsyncProcess](ctx, c, "/keys/async-processes", query)
}

// GetKeyAsyncProcess fetches one key-scoped async process record, including
// its request and response bodies (AsyncKeyProcessModel). Poll it until
// Status is [AsyncProcessFinished] or [AsyncProcessError]; the SDK
// deliberately provides no polling loop.
func (c *Client) GetKeyAsyncProcess(ctx context.Context, id uuid.UUID) (AsyncProcess, error) {
	var result AsyncProcess
	if err := c.do(ctx, http.MethodGet, "/keys/async-processes/"+id.String(), nil, true, &result); err != nil {
		return AsyncProcess{}, err
	}
	return result, nil
}

// DeleteKeyAsyncProcess deletes the stored content (request, response,
// output) of a finished key-scoped async process.
func (c *Client) DeleteKeyAsyncProcess(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodDelete, "/keys/async-processes/"+id.String(), nil, true, nil)
}

// GetVSlotAsyncProcesses lists the async processes of vslot-scoped plugin
// operations, iterating server pages transparently
// (AsyncVslotProcessSearchResultModel).
func (c *Client) GetVSlotAsyncProcesses(ctx context.Context) ([]AsyncProcess, error) {
	query := url.Values{}
	query.Set("sort", "creationDate,desc")
	return fetchAllPages[AsyncProcess](ctx, c, "/vslots/async-processes", query)
}

// GetVSlotAsyncProcess fetches one vslot-scoped async process record,
// including its request and response bodies (AsyncVslotProcessModel).
func (c *Client) GetVSlotAsyncProcess(ctx context.Context, id uuid.UUID) (AsyncProcess, error) {
	var result AsyncProcess
	if err := c.do(ctx, http.MethodGet, "/vslots/async-processes/"+id.String(), nil, true, &result); err != nil {
		return AsyncProcess{}, err
	}
	return result, nil
}

// DeleteVSlotAsyncProcess deletes the stored content (request, response,
// output) of a finished vslot-scoped async process.
func (c *Client) DeleteVSlotAsyncProcess(ctx context.Context, id uuid.UUID) error {
	return c.do(ctx, http.MethodDelete, "/vslots/async-processes/"+id.String(), nil, true, nil)
}
