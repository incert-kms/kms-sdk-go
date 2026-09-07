# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- TLS options for the SDK-managed HTTP client: `WithTLSCACert(file)` and
  `WithTLSCAPath(dir)` set PEM trust anchors that replace the system roots (the
  directory is walked recursively and files without certificates are skipped),
  `WithTLSClientCert(certFile, keyFile)` presents a client certificate for
  mutual TLS, `WithTLSServerName(name)` sets the name used for SNI and
  verification, and `WithTLSConfig(cfg)` supplies a base `*tls.Config` (cloned)
  that the other options layer onto. The material is loaded by `NewClient`; a
  load failure is reported by `Connect` as `tls configuration: ...` before any
  request is made. The identity provider's token requests share the transport,
  so the settings apply to them as well.

### Changed

- `WithHTTPClient` now takes precedence over every `WithTLS*` option
  (previously only `WithTLSSkipVerify`) and logs a single warning when both are
  supplied. `NewClient` is documented as performing no *network* I/O, since it
  reads the files named by the TLS options.
- `WithTLSSkipVerify` combined with CA material or a server name logs a warning
  that those are not verified.

## [1.3.0] - 2026-09-07

### Added

- **Key lifecycle**: `Client.SetKeyState` (`POST /keys/{id}/state`) for the
  forward-only state transitions and enabled toggling, and `Client.RotateKey`
  (`POST /keys/{id}/rotate`) returning the successor key id discovered by
  re-reading the key's links around the (empty-bodied) rotation; the sentinel
  `ErrSuccessorUnknown` distinguishes "rotated but successor not identified"
  from a failed rotation.
- **Key aliases**: `Client.FindKeyAliases`, `Client.CreateKeyAlias` and
  `Client.MoveKeyAlias` (`GET /keys/aliases`, `POST /keys/{id}/alias`) with the
  new `KeyAlias` model — stable handles that survive rotation.
- **Key material operations** (`application/kms.key+json`): `Client.ExportKey`
  (`POST /keys/{id}/p/export`), `Client.ImportKey` (`POST /vslots/{id}/p/ki`),
  `Client.ImportKeyValues` (`POST /keys/{id}/p/ki`), `Client.AttachKey`
  (`POST /vslots/{id}/p/ka`) and `Client.EditKey` (`POST /keys/{id}/p/edit`),
  plus `KeyValueType*` and `KeyFormat*` constants for the key-value type and
  format enums.
- **Derive and transport**: `Client.DeriveKey` (`POST /keys/{id}/p/derive`,
  `application/kms.derive+json`, new `DeriveRequest` model) and
  `Client.TransportKey` (`POST /keys/{id}/transport`,
  `application/kms.transport+json`).
- **Sign flavors** — one method per media type on `POST /keys/{id}/p/sign`:
  `Client.SignSOD` (`application/kms.sign-sod+json`, `SignSODRequest`),
  `Client.SignTimestamp` (`application/kms.sign-timestamp+json`,
  `SignTimestampRequest`) and `Client.SignPDF` (`application/kms.sign+pdf`).
- **Certificate operations**: `Client.GenerateCertificate`,
  `Client.GenerateCSR` and `Client.UpdateCertificate`
  (`POST /keys/{id}/p/{certgen,csrgen,certupdate}`,
  `application/kms.certificate+json`, new `CertificateRequest` model including
  the `storeInDb` flag of servers >= 4.3.2.1).
- **Async process queries**: `Client.GetKeyAsyncProcesses`,
  `Client.GetKeyAsyncProcess`, `Client.DeleteKeyAsyncProcess` and their vslot
  mirrors, with the new `AsyncProcess` model and status constants. Triggering
  operations with `async=true` remains on the roadmap.
- **Generic OIDC authentication** (`provider: OTHER` — Auth0, Okta): password
  grant against the token endpoint from discovery (resolved against the
  provider's own URL), the usable token selected by `accessTokenProperty`
  (camel-case config mapped to the snake_case wire), refresh grant with
  password-grant fallback, and the new `WithClientSecret` option for
  confidential clients.
- **HTTP 260 handling**: the success-shaped `INTERNAL_KEY_ATTRIBUTES_DIFFERENT`
  status now surfaces as a `*APIError` (`StatusCode` 260) on every endpoint
  instead of silently decoding its error body into an empty result.
- **Correlation ids**: `WithCorrelationID(ctx, id)` sends the
  `X-Correlation-Id` header (honored by servers >= 4.3.0.4, ignored by older
  ones, reused on the 401 replay), and the new `APIError.CorrelationID` field
  captures the id echoed on error responses.
- `KeyFilter` gained `AliasID`, `Type`, `Alg`, `Persistence`, `State` and
  `Enabled` fields for `Client.FindKeys`.

### Changed

- README and package documentation cover the new operations; `SPEC.md` is added
  as the in-repo wire contract and roadmap of unimplemented operations.

## [1.2.0] - 2026-07-21

### Added

- `Client.Sign` and `Client.Verify` (`POST /keys/{id}/p/sign|verify`,
  `application/kms.sign+json`) with the new `SignRequest` /
  `SignatureAttributes` models: the signature to verify travels in
  `attributes.signature`, and `RSA_PKCS-PSS_RAW` parameters
  (`hashAlg`/`mgf`/`saltLength`) as numeric PKCS#11 codes. A wrong
  signature yields `(false, nil)`, mirroring the server's
  `{"valid": false}` response.

### Breaking changes

- The configured base URL no longer includes the `/api` prefix — the SDK
  appends it internally, aligning with the API documentation's convention
  that `{base}` is the deployment root and every REST path lives under
  `{base}/api/...`. Migration: drop the trailing `/api` from `WithBaseURL`
  (`WithBaseURL("https://kms.example.com/kms/api")` →
  `WithBaseURL("https://kms.example.com/kms")`). The default base URL
  changed accordingly to `https://kms-uat.incert.lu/kms`. Note: a
  *relative* Keycloak URL from auth discovery now resolves against the
  deployment root instead of the `/api` root (absolute and root-relative
  Keycloak URLs are unaffected).

## [1.1.0] - 2026-07-17

Conformance, concurrency and robustness release, aligning the SDK with the
Keys&More API documentation.

> **⚠ Breaking changes.** As announced in the README, the SDK is under
> development and this release changes several public signatures. See
> *Breaking changes* below for the migration notes.

### Breaking changes

- `NewClient` no longer takes a `context.Context` (it performs no I/O).
  Migration: `NewClient(ctx, opts...)` → `NewClient(opts...)`.
- `CreateKey` now takes the vslot first and a `KeyData` request model, and
  returns a `KeyDataResponse` instead of echoing the input:
  `CreateKey(ctx, key KeyDetail, vslotID)` → `CreateKey(ctx, vslotID, key KeyData) (KeyDataResponse, error)`.
  `KeyData` matches the wire model (`KeyDataModel`): key material is sent under
  `values` (previously the unrecognized `keyValues`), and the new `Data` field
  is supported.
- `CryptoRequest.Attributes` changed from the `Attributes` struct (IV only) to
  `map[string]any`, so all documented algorithm attributes are expressible
  (`iv`, `counter`, `aad`, `label`, `multi`, ...). The `Attributes` struct was
  removed. Migration: `Attributes: kmssdk.Attributes{IV: iv}` →
  `Attributes: map[string]any{"iv": iv}`.
- OAuth2 naming now follows Go initialism conventions: `Oauth2Provider`,
  `Oauth2Config`, `Oauth2ClaimsConfig`, `Oauth2KeycloakConfig`,
  `Oauth2OtherConfig`, `Oauth2ProviderKeycloak` are now `OAuth2*`, and
  `Config.Oauth2` is now `Config.OAuth2`.
- The `Oauth2` type and `NewOauth2` constructor were removed from the public
  API; the client consumes the new `TokenSource` interface
  (`GetToken(ctx) (string, error)`) instead.
- `KeyUseAttributes` boolean fields no longer carry `omitempty`: when the
  struct is present in a request, all eight flags are serialized so explicit
  `false` values (e.g. `extractable: false`) reach the server instead of
  silently falling back to server defaults.
- `Client.Crypto` now rejects operations other than `OperationEncrypt` /
  `OperationDecrypt` instead of sending them with the encrypt media type.

### Added

- **Self-managed authentication** (`type: SELF_MANAGED`): `Connect` now
  selects the authentication backend from the discovery config. On
  self-managed deployments the client logs in via `POST /auth/token`, renews
  the access token via `POST /auth/token/refresh` (keeping the login refresh
  token, per the TOKEN API contract), and falls back to a fresh login when the
  refresh is rejected. The new `Client.Logout` deactivates the tokens
  server-side (`POST /auth/token/logout`); on OAuth2 deployments it drops the
  cached token locally.
- Keycloak **realm and client id are taken from the server's discovery
  config** (`GET /configs/auth`) instead of being hardcoded; `kms`/`kms`
  remain fallbacks for empty values.
- **Automatic 401 recovery**: when an authenticated request is rejected with
  401 (e.g. token revoked before its local expiry), the cached token is
  invalidated and the request replayed once with a fresh token.
- **Refresh-grant fallback**: a refresh token rejected by the IdP (4xx) is
  dropped and the password grant is retried in the same call, instead of the
  failure persisting until the local refresh expiry.
- **Full pagination**: `GetVSlots`, `GetKeys` and `FindKeys` iterate all
  server pages until `last: true` — previously a single `size=10000` page was
  fetched and further data silently dropped.
- `WithTimeout(d)` option for the SDK-managed HTTP client (default 10s).
- `KeyDataResponse` surfaces the `values` returned by key creation — for
  `persistence: NONE` keys, that response is the only chance to capture the
  generated material.
- Typed constants: the 19 server error codes (`ErrCode*`), key lifecycle
  states (`KeyState*`), persistence modes (`Persistence*`) and key types
  (`KeyType*`).
- `APIError.Errors` carries the per-field validation messages of
  bean-validation failures.
- `TokenSource` interface as the extension point for future auth backends
  (self-managed, generic OAuth2/OIDC, device grant).
- Godoc comments on every exported identifier and runnable `Example*`
  functions (`example_test.go`).
- `Accept: application/json` header on all requests, per the API conventions.

### Fixed

- **Data race in token handling**: token cache reads/writes are now
  mutex-guarded; the client is safe for concurrent use once `Connect` has
  returned (also prevents concurrent refresh stampedes).
- Error responses in the *framework fallback* shape no longer have their
  message overwritten by the `error` field (previously reduced to e.g.
  `"400 BAD_REQUEST ()"`); IdP `error`/`error_description` fields are folded
  in only when no message is present.
- Inverted condition in `newAPIError` that made the caller-supplied fallback
  message dead code.
- Nil-pointer panics replaced with descriptive errors: `type: OAUTH2` config
  without an `oauth2`/`keycloak` section, and any authenticated call made
  before `Connect`.
- `WithTLSSkipVerify` is no longer option-order-dependent, no longer mutates a
  caller-supplied `*http.Client`, and clones `http.DefaultTransport` (keeping
  proxy settings, timeouts and HTTP/2) instead of installing a bare transport.
- Response bodies are drained before close so keep-alive connections are
  reused (previously never reused on empty-result calls such as `DeleteKey`).
- The pagination truncation warning compared against an impossible threshold
  and could never fire (superseded by full page iteration).
- `WithBaseURL` trims trailing slashes to avoid `//` request paths.

### Changed

- `DeleteKey` documentation corrected: posting the `DELETED` state is an
  immediate permanent removal of key material and metadata, not a soft delete.
- `examples/main.go` reads its configuration from environment variables
  (`KMS_BASE_URL`, `KMS_USERNAME`, `KMS_PASSWORD`, `KMS_VSLOT_ID`) instead of
  hardcoded credentials, and no longer disables TLS verification.
- README updated for the new signatures, options and error-handling guidance.

## [1.0.1] - 2025

- Go toolchain version update.

## [1.0.0] - 2025

- Initial release: Keycloak OAuth2 bootstrap (`Connect`), vslot listing, key
  search/read/create/delete, and encrypt/decrypt operations.

[Unreleased]: https://github.com/incert-kms/kms-sdk-go/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/incert-kms/kms-sdk-go/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/incert-kms/kms-sdk-go/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/incert-kms/kms-sdk-go/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/incert-kms/kms-sdk-go/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/incert-kms/kms-sdk-go/releases/tag/v1.0.0
