// Package kmssdk provides a Go client for the incert KMS HTTP API.
//
// Authentication uses OAuth2 with a Keycloak provider; the client discovers
// the Keycloak URL from the KMS server's /configs/auth endpoint and obtains
// a token via the password grant.
//
// # Getting started
//
// Construct a client with the desired options, then call [Client.Connect]
// once to bootstrap authentication and verify access:
//
//	client := kmssdk.NewClient(
//	    context.Background(),
//	    kmssdk.WithBaseURL("https://kms.example.com/kms/api"),
//	    kmssdk.WithUsernameAndPassword("user", "pass"),
//	    kmssdk.WithLogger(slog.Default()),
//	)
//	if err := client.Connect(ctx); err != nil {
//	    // handle error
//	}
//
// Available options:
//   - [WithBaseURL] overrides the default API base URL.
//   - [WithUsernameAndPassword] sets the credentials used for the Keycloak
//     password grant.
//   - [WithTLSSkipVerify] disables TLS verification (development only).
//   - [WithHTTPClient] supplies a custom *http.Client.
//   - [WithLogger] supplies a *slog.Logger; without it the SDK is silent.
//
// # Operations
//
// Vslots and keys:
//   - [Client.GetVSlots] lists vslots.
//   - [Client.GetKeys] and [Client.FindKeys] list keys in a vslot, optionally
//     filtered with a [KeyFilter].
//   - [Client.GetKey] fetches a single key by ID.
//   - [Client.CreateKey] creates a key in a vslot.
//   - [Client.DeleteKey] soft-deletes a key by transitioning its state to
//     DELETED.
//
// Cryptographic operations are issued through [Client.Crypto] with either
// [OperationEncrypt] or [OperationDecrypt]:
//
//	ciphertext, err := client.Crypto(ctx, kmssdk.OperationEncrypt, keyID, kmssdk.CryptoRequest{
//	    Data:       plaintext,
//	    Algorithm:  "AES_GCM",
//	    Attributes: kmssdk.Attributes{IV: iv},
//	})
//
// # Errors
//
// API errors are returned as [*APIError]. Use errors.As to inspect the HTTP
// status code, server error code, and message:
//
//	var apiErr *kmssdk.APIError
//	if errors.As(err, &apiErr) {
//	    fmt.Printf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
//	}
//
// # Context
//
// Every method accepts a [context.Context] for cancellation and timeouts.
package kmssdk
