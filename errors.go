package kmssdk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type APIError struct {
	StatusCode       int    `json:"status_code"`
	Timestamp        string `json:"timestamp"`
	Message          string `json:"message"`
	Code             string `json:"code"`
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kms-sdk-go: %d %s: %s", e.StatusCode, e.Code, e.Message)
}

func newAPIError(resp *http.Response, message ...string) error {
	apiErr := &APIError{StatusCode: resp.StatusCode}
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
		// Keycloak returns error and error_description fields, so set them in the message field
		if apiErr.ErrorCode != "" {
			apiErr.Message = fmt.Sprintf(
				"%s (%s)",
				apiErr.ErrorCode,
				apiErr.ErrorDescription,
			)
		}
	}

	// If optional message is provided, use it as the error message if the message could not be unmarshalled from the response body
	if len(message) > 0 && message[0] == "" {
		apiErr.Message = message[0]
	}
	return apiErr
}
