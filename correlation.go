package kmssdk

import "context"

// headerCorrelationID is the request/response header carrying the correlation
// id, honored by servers >= 4.3.0.4.
const headerCorrelationID = "X-Correlation-Id"

// correlationIDKey is the context key under which [WithCorrelationID] stores a
// caller-supplied correlation id.
type correlationIDKey struct{}

// WithCorrelationID returns a context that makes the SDK send the given id as
// the X-Correlation-Id header on every request issued with it. Servers
// >= 4.3.0.4 echo the id on the response (see [APIError.CorrelationID]) and
// reference it in internal-error messages; older servers ignore the header.
// Without a caller-supplied id the server generates one itself. The same id is
// reused when a request is replayed after a 401.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey{}, id)
}
