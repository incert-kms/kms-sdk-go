package kmssdk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Server error codes (the ApiErrorCode enum) carried in [APIError.Code].
// Branch on these rather than on [APIError.Message]: messages are
// human-oriented and may change between server versions.
const (
	ErrCodeBadRequest                    = "BAD_REQUEST"                       // 400
	ErrCodeWrongCredentials              = "WRONG_CREDENTIALS"                 //nolint:gosec // server error-code name, not a credential — 401
	ErrCodeInvalidToken                  = "INVALID_TOKEN"                     // 401
	ErrCodeDeactivatedToken              = "DEACTIVATED_TOKEN"                 // 401
	ErrCodeInvalidSignature              = "INVALID_SIGNATURE"                 // 401
	ErrCodeUnauthorized                  = "UNAUTHORIZED"                      // 401
	ErrCodeForbiddenAccess               = "FORBIDDEN_ACCESS"                  // 403
	ErrCodeForbiddenOperation            = "FORBIDDEN_OPERATION"               // 403
	ErrCodeTooManyResults                = "TOO_MANY_RESULTS"                  // 403
	ErrCodeDisabledAccount               = "DISABLED_ACCOUNT"                  // 403
	ErrCodeEmailVerificationTokenInvalid = "EMAIL_VERIFICATION_TOKEN_INVALID"  //nolint:gosec // server error-code name, not a credential — 400/401
	ErrCodeResourceNotFound              = "RESOURCE_NOT_FOUND"                // 404
	ErrCodeConflict                      = "CONFLICT"                          // 409
	ErrCodeInvalidMultipart              = "INVALID_MULTIPART"                 // 415
	ErrCodeQuotaExceeded                 = "QUOTA_EXCEEDED"                    // 429
	ErrCodeInternalServerError           = "INTERNAL_SERVER_ERROR"             // 500
	ErrCodeKeyLifecycle                  = "KEY_LIFECYCLE"                     // 500
	ErrCodeNotImplemented                = "NOT_IMPLEMENTED"                   // 501
	ErrCodeInternalKeyAttributesDiffer   = "INTERNAL_KEY_ATTRIBUTES_DIFFERENT" // 260 (non-standard)
)

// statusKeyAttributesDifferent is the non-standard, success-shaped HTTP status
// the server uses exclusively for INTERNAL_KEY_ATTRIBUTES_DIFFERENT (the
// attach/import consistency check). It carries an error-shaped body, so do()
// folds it into the error path.
const statusKeyAttributesDifferent = 260

// APIError is returned for every HTTP response with status >= 400 — from both
// the KMS API and the OAuth2 token endpoint — and for the non-standard,
// success-shaped status 260 (INTERNAL_KEY_ATTRIBUTES_DIFFERENT). Inspect it
// with errors.As:
//
//	var apiErr *kmssdk.APIError
//	if errors.As(err, &apiErr) {
//	    switch {
//	    case apiErr.Code == kmssdk.ErrCodeResourceNotFound:
//	        // ...
//	    case apiErr.StatusCode >= 500:
//	        // server-side failure, possibly transient
//	    }
//	}
//
// Errors that never reached the server (connection failures, timeouts) are not
// APIError values: they wrap the underlying *url.Error, so
// errors.Is(err, context.DeadlineExceeded) and os.IsTimeout(err) keep working.
type APIError struct {
	// StatusCode is the HTTP status of the response.
	StatusCode int `json:"status_code"`
	// Timestamp is set when the server reports one (framework fallback errors).
	Timestamp string `json:"timestamp"`
	// Message is the human-readable server message.
	Message string `json:"message"`
	// Code is the server error code (one of the ErrCode* constants), or the
	// HTTP status text when the server did not provide one.
	Code string `json:"code"`
	// Errors holds per-field validation messages, populated only for
	// bean-validation failures (Code == ErrCodeBadRequest).
	Errors []string `json:"errors"`
	// ErrorCode and ErrorDescription carry the OAuth2 IdP-native error fields
	// ("error", "error_description") returned by token endpoints.
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	// CorrelationID is the X-Correlation-Id header echoed on the response by
	// servers >= 4.3.0.4 (empty on older servers). It identifies the request
	// in the server logs; internal-error messages reference it. It comes from
	// the response header, never from the body.
	CorrelationID string `json:"-"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("kms-sdk-go: %d %s: %s", e.StatusCode, e.Code, e.Message)
}

// newAPIError builds an *APIError from a non-2xx response, handling the three
// documented body shapes: the standard ApiErrorModel ({code, message, errors}),
// the framework fallback ({timestamp, status, error, message, path}), and the
// IdP-native OAuth2 shape ({error, error_description}). The optional message is
// used as a fallback when the body yields none.
func newAPIError(resp *http.Response, message ...string) error {
	apiErr := &APIError{
		StatusCode:    resp.StatusCode,
		CorrelationID: resp.Header.Get(headerCorrelationID),
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, apiErr); err != nil {
		// Couldn't unmarshal the error response, fallback to the HTTP status
		apiErr.Message = resp.Status
		apiErr.Code = http.StatusText(resp.StatusCode)
	} else {
		// If the code is empty, use the HTTP status text
		if apiErr.Code == "" {
			apiErr.Code = http.StatusText(resp.StatusCode)
		}
		// OAuth2 token endpoints return error and error_description instead of
		// a message; fold them in only when no message was provided.
		if apiErr.Message == "" && apiErr.ErrorCode != "" {
			apiErr.Message = fmt.Sprintf(
				"%s (%s)",
				apiErr.ErrorCode,
				apiErr.ErrorDescription,
			)
		}
	}

	// http.StatusText knows no 260, so a 260 without a body code would end up
	// with an empty Code; default it to the one code 260 stands for.
	if apiErr.Code == "" && resp.StatusCode == statusKeyAttributesDifferent {
		apiErr.Code = ErrCodeInternalKeyAttributesDiffer
	}

	// If an optional message is provided, use it when the response body did not
	// yield one.
	if len(message) > 0 && message[0] != "" && apiErr.Message == "" {
		apiErr.Message = message[0]
	}
	return apiErr
}
