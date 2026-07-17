# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
Keys&More API documentation (`api-doc/`).

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

[1.1.0]: https://github.com/incert-kms/kms-sdk-go/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/incert-kms/kms-sdk-go/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/incert-kms/kms-sdk-go/releases/tag/v1.0.0
