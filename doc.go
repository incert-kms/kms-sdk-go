// Package kmssdk provides a Go client for the INCERT Keys&More KMS HTTP API.
//
// The client discovers the server's authentication mode from the public
// /configs/auth endpoint and picks the matching backend automatically:
//
//   - SELF_MANAGED: tokens are issued by Keys&More itself; the client logs in
//     with username/password (POST /auth/token) and renews the access token
//     via the refresh endpoint.
//   - OAUTH2 with a Keycloak provider: the Keycloak URL, realm and client id
//     come from discovery and a token is obtained via the password grant.
//   - OAUTH2 with a generic OIDC provider (OTHER — e.g. Auth0 or Okta): the
//     password grant runs against the token endpoint from discovery;
//     confidential clients supply [WithClientSecret].
//
// In all modes tokens are cached and renewed transparently, and
// [Client.Logout] invalidates them (server-side on SELF_MANAGED deployments).
//
// # Getting started
//
// Construct a client with the desired options, then call [Client.Connect]
// once to bootstrap authentication and verify access:
//
//	ctx := context.Background()
//	client := kmssdk.NewClient(
//	    kmssdk.WithBaseURL("https://kms.example.com/kms"),
//	    kmssdk.WithUsernameAndPassword("user", "pass"),
//	    kmssdk.WithLogger(slog.Default()),
//	)
//	if err := client.Connect(ctx); err != nil {
//	    // handle error
//	}
//
// Available options:
//   - [WithBaseURL] overrides the default deployment base URL (the /api
//     prefix is appended internally).
//   - [WithUsernameAndPassword] sets the credentials used for the password
//     grant / self-managed login.
//   - [WithClientSecret] sets the OAuth2 client secret for confidential
//     clients (provider OTHER).
//   - [WithTimeout] adjusts the HTTP timeout (default 10s).
//   - [WithTLSSkipVerify] disables TLS verification (development only).
//   - [WithHTTPClient] supplies a custom *http.Client (takes precedence over
//     WithTimeout and WithTLSSkipVerify).
//   - [WithLogger] supplies a *slog.Logger; without it the SDK is silent.
//
// # Operations
//
// Vslots and keys:
//   - [Client.GetVSlots] lists vslots.
//   - [Client.GetKeys] and [Client.FindKeys] list keys in a vslot, optionally
//     filtered with a [KeyFilter]. Paged responses are iterated transparently.
//   - [Client.GetKey] fetches a single key by ID.
//   - [Client.CreateKey] generates a key in a vslot from a [KeyData]
//     description and returns a [KeyDataResponse] with the new key's ID (and,
//     for persistence NONE, the generated material).
//   - [Client.SetKeyState] advances the forward-only lifecycle and toggles
//     the enabled flag; [Client.DeleteKey] permanently deletes a key by
//     posting the DELETED lifecycle state.
//   - [Client.RotateKey] creates a successor key and returns its id;
//     [Client.FindKeyAliases], [Client.CreateKeyAlias] and
//     [Client.MoveKeyAlias] manage the stable aliases that survive rotation.
//   - [Client.ExportKey], [Client.ImportKey], [Client.ImportKeyValues],
//     [Client.AttachKey] and [Client.EditKey] move key material in and out of
//     the KMS and edit use attributes through the provider plugin.
//   - [Client.DeriveKey] derives a new key; [Client.TransportKey] re-wraps a
//     key into another vslot.
//   - [Client.GetKeyAsyncProcesses], [Client.GetKeyAsyncProcess],
//     [Client.DeleteKeyAsyncProcess] and their vslot mirrors inspect the
//     records of asynchronously executed operations.
//
// Cryptographic operations are issued through [Client.Crypto] with either
// [OperationEncrypt] or [OperationDecrypt]:
//
//	ciphertext, err := client.Crypto(ctx, kmssdk.OperationEncrypt, keyID, kmssdk.CryptoRequest{
//	    Data:       plaintext,
//	    Algorithm:  "AES_GCM",
//	    Attributes: map[string]any{"iv": iv},
//	})
//
// [Client.Sign] and [Client.Verify] cover the signature registry;
// [Client.SignSOD], [Client.SignTimestamp] and [Client.SignPDF] produce ICAO
// SODs, RFC 3161 timestamp responses and signed PDFs; and
// [Client.GenerateCertificate], [Client.GenerateCSR] and
// [Client.UpdateCertificate] handle certificates on a key.
//
// # Errors
//
// API errors are returned as [*APIError]. Use errors.As to inspect the HTTP
// status code, server error code (see the ErrCode constants), and message:
//
//	var apiErr *kmssdk.APIError
//	if errors.As(err, &apiErr) {
//	    fmt.Printf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
//	}
//
// Network-level failures (connection errors, timeouts) are not APIError
// values; they wrap the underlying transport error, so
// errors.Is(err, context.DeadlineExceeded) and os.IsTimeout(err) apply.
//
// # Concurrency
//
// After [Client.Connect] returns, the client is safe for concurrent use by
// multiple goroutines; token renewal is synchronized internally. Connect
// itself must complete before concurrent calls start.
//
// # Context
//
// Every method accepts a [context.Context] for cancellation and timeouts.
package kmssdk
