# kms-sdk-go specification

This document specifies what the SDK does, the server wire contract it implements, and a
coverage map of the Keys&More REST API to orient future development. It is the
self-contained reference for this repository: the behavior described here is asserted by
the test suite, and new operations should be designed against the contract stated here.

- Module: `github.com/incert-kms/kms-sdk-go`, package `kmssdk` (import as
  `kmssdk "github.com/incert-kms/kms-sdk-go"`).
- Target service: INCERT Keys&More KMS, REST API (product line 4.2.x/4.3.x). The API is
  unversioned — there is no `/v1/` path segment; compatibility follows the server
  release line.
- Scope: authentication, vslot listing, key management, and cryptographic operations.
  PKI, administration, TSA, JWKS/CRL distribution, and KMIP are out of scope (§8).
- Versioning: SemVer via Go modules. While the README carries the under-development
  notice, breaking changes may ship in minor releases and are documented in
  `CHANGELOG.md` with explicit `old → new` migration lines.

## 1. Design principles

1. **One client, thin operations.** All functionality hangs off `*Client`. Every
   operation is a small typed wrapper over the single request chokepoint
   `Client.do(ctx, method, path, body, authenticated, result, contentType...)` —
   operations never hand-roll HTTP.
2. **Functional options.** `NewClient(opts ...Option)` performs no network I/O (files
   named by `WithTLS*` options are read at construction; load failures surface from
   `Connect`); `Connect(ctx)` does the authentication bootstrap. Configuration is
   immutable after construction.
3. **`context.Context` first.** Every exported method and every internal I/O helper
   takes a context as its first parameter; cancellation and deadlines propagate to the
   HTTP layer via `http.NewRequestWithContext`.
4. **Base64 by construction.** All binary material on the wire (plaintext, ciphertext,
   signatures, key values, wrap keys) is base64 inside JSON. SDK models use `[]byte`
   fields, which `encoding/json` marshals to base64 natively — callers and new
   operations never encode manually.
5. **Typed errors.** Every HTTP response with status ≥ 400 — from the KMS API and from
   token endpoints — becomes a `*APIError` inspectable with `errors.As`. Transport
   failures are wrapped with `%w` instead, so `errors.Is(err, context.DeadlineExceeded)`
   and `os.IsTimeout(err)` keep working.
6. **Minimal dependencies.** Standard library plus `github.com/google/uuid` only.
7. **Silent by default.** Diagnostics go to a `*slog.Logger` that defaults to
   `slog.DiscardHandler`; `WithLogger` opts in.
8. **Concurrency-safe after Connect.** Once `Connect` has returned, the client is safe
   for concurrent use. Token caches are guarded by a mutex held across the whole
   refresh, which serializes renewals and prevents refresh stampedes.

## 2. Wire contract

### 2.1 Base URL

- The configured base URL (`WithBaseURL`) is the **deployment root without `/api`**,
  e.g. `https://kms.example.com/kms` (servers commonly sit behind a context path such
  as `/kms` or `/kms1`). A trailing slash is trimmed.
- The SDK appends `/api` internally exactly once at construction
  (`apiURL = baseURL + "/api"`); every path in this document and in code is relative to
  that API root.
- The default base URL points at INCERT's UAT environment
  (`https://kms-uat.incert.lu/kms`) and must be overridden for production.
- **Asymmetry (deliberate):** a root-relative or relative Keycloak URL from discovery
  resolves against the *base* URL (scheme + host + path), not the API URL — Keycloak is
  not served under `/api`.

### 2.2 Authentication

Everything except `GET /configs/auth` requires `Authorization: Bearer <access-token>`.
`Connect` implements the bootstrap:

1. `GET /configs/auth` (public) returns the deployment's authentication configuration
   (`AuthenticationConfigModel`): `type`, optional `oauth2` section with `provider`,
   claim mappings, and provider coordinates.
2. Branch on `type`:
   - **`SELF_MANAGED`** — Keys&More issues its own JWTs through the TOKEN API (this is
     the server's default mode). Login: `POST /auth/token` with JSON
     `{"username", "password"}`. Renewal: `POST /auth/token/refresh` with
     `{"refresh_token"}`. Invalidation: `POST /auth/token/logout` with
     `{"access_token", "refresh_token"}` → 204. These endpoints exist **only** on
     self-managed deployments. Responses use **snake_case**
     (`access_token`, `expires_in`, `refresh_token`, `refresh_expires_in`), unlike the
     rest of the API. Typical lifetimes: access 300 s, refresh 3600 s. A refresh
     response carries **no new refresh token** — the one obtained at login is retained
     until it expires or is rejected.
   - **`OAUTH2` + `provider: KEYCLOAK`** — resource-owner password grant against
     `{keycloak}/realms/{realm}/protocol/openid-connect/token` with
     `client_id` from discovery. The Keycloak URL from discovery may be absolute,
     root-relative (`/auth`), or relative (`auth`) — the SDK resolves it against the
     base URL. Empty realm/clientId fall back to the conventional defaults
     `kms`/`kms`.
   - **`OAUTH2` + `provider: OTHER`** (generic OIDC — Auth0, Okta) — resource-owner
     password grant against `tokenEndpoint` from discovery, resolved against the
     provider's own `url` (not the KMS base URL) when relative. The form carries
     `client_id`, `scope=openid`, `audience` when configured, and `client_secret`
     when supplied via `WithClientSecret` (confidential clients; there is no
     discovery field for it). The usable token is the response property named by
     `accessTokenProperty` — camel-case in discovery (default `accessToken`,
     e.g. `idToken`) while the wire is snake_case; the SDK tries the literal
     spelling first, then the snake_case form. A token without `expires_in` is
     cached until the server rejects it (the 401 replay corrects that); a
     `refresh_token`, when issued, is used for renewal with password-grant
     fallback on 4xx. No server-side logout flow exists for OTHER — `Logout`
     drops the token locally. `tokenEndpoint` and `clientId` are required in
     discovery (no conventional defaults, unlike Keycloak).
3. Cache the token pair with expiries computed from `expires_in` /
   `refresh_expires_in`. On expiry, renew with the refresh grant; when the refresh is
   rejected with a 4xx, drop the refresh token and fall back to a fresh
   password grant / login in the same call (5xx propagates).
4. Smoke-test authenticated access with `GetVSlots`.

**401 replay:** when an authenticated request is rejected with 401 (a token revoked
before its local expiry — `INVALID_TOKEN`, `DEACTIVATED_TOKEN`, ...), the SDK
invalidates the cached access token and replays the request **exactly once** with a
fresh token. No expiry skew is subtracted client-side; the replay is what absorbs
clock differences. There is deliberately **no** other retry: no backoff, no retry on
5xx or transport errors. (Rationale: some server operations are not idempotent even
when they look it — see §7.)

**Extension point:** the `TokenSource` interface
(`GetToken(ctx context.Context) (string, error)`, implementations must be
concurrency-safe) is what `do()` consumes. Backends additionally implementing
`InvalidateToken()` participate in the 401 replay, and backends implementing
`Logout(ctx) error` get server-side invalidation via `Client.Logout`.

### 2.3 Vendor media types

Management endpoints use `application/json`. The plugin-style operation endpoints
(`/p/*`) use **vendor media types**: the `Content-Type` header selects the request
schema, and plain `application/json` is rejected with 415. The SDK passes the media
type per call via `do()`'s variadic `contentType` argument.

| Media type | Endpoints | Request schema | SDK status |
|---|---|---|---|
| `application/kms.key+json` | `POST /vslots/{v}/p/kg`, `p/ki`, `p/ka`; `POST /keys/{k}/p/ki`, `p/export`, `p/edit` | `KeyDataModel` | `CreateKey`, `ImportKey`, `AttachKey`, `ImportKeyValues`, `ExportKey`, `EditKey` |
| `application/kms.encrypt+json` | `POST /keys/{k}/p/encrypt`, `p/decrypt` | `EncryptDataModel` | `Crypto` |
| `application/kms.sign+json` | `POST /keys/{k}/p/sign`, `p/verify` | `SignatureDataModel` | `Sign`, `Verify` |
| `application/kms.sign-sod+json` | `POST /keys/{k}/p/sign` (ICAO SOD) | `SignatureSodDataModel` | `SignSOD` |
| `application/kms.sign-timestamp+json` | `POST /keys/{k}/p/sign` (RFC 3161) | `SignatureTimestampDataModel` | `SignTimestamp` |
| `application/kms.sign+pdf` | `POST /keys/{k}/p/sign` (PDF) | `{"data": "<base64 PDF>"}` | `SignPDF` |
| `application/kms.derive+json` | `POST /keys/{k}/p/derive` | `DeriveDataModel` | `DeriveKey` |
| `application/kms.transport+json` | `POST /keys/{k}/transport` | `KeyTransportModel` | `TransportKey` |
| `application/kms.certificate+json` | `POST /keys/{k}/p/certgen`, `p/csrgen`, `p/certupdate` | `CertificateDataModel` | `GenerateCertificate`, `GenerateCSR`, `UpdateCertificate` |

Transport caveat: some deployments document plain `application/json` on
`POST /keys/{k}/transport` instead of the vendor type the SDK sends. A 415 on
this endpoint means the deployment expects the other form; the media type is a
single string in `TransportKey` if it ever needs flipping.

Note that `POST /keys/{k}/p/sign` alone dispatches **four** request schemas by
Content-Type. Each flavor therefore gets its own SDK method — do not widen an existing
method with a mode flag.

### 2.4 Encoding conventions

- Binary values: base64 in JSON (`[]byte` in Go models). This includes short values
  (KCVs, provider ids) and the OAEP `label` attribute.
- Timestamps: ISO-8601 with offset (`2023-03-21T10:15:30+01:00` or `...Z`).
- RSA-PSS raw parameters (`hashAlg`, `mgf`, `saltLength`) are **numeric PKCS#11
  constants**, e.g. `hashAlg: 592` (= CKM_SHA256), `mgf: 2` (= CKG_MGF1_SHA256).
- The `algorithm` field accepts a compact string identifier (preferred, §6) or a legacy
  nested-object form (`{"algorithm":"AES","scheme":"CBC","padding":"PKCS7"}`). The SDK
  models `algorithm` as `string`; the object form is treated as legacy compatibility
  the SDK does not emit.

### 2.5 Pagination

List endpoints return a Spring-style page envelope driven by `page` (0-based), `size`,
and `sort` (`field,asc|desc`) query parameters:

```json
{ "content": [...], "totalPages": 3, "totalElements": 25000, "first": true, "last": false }
```

The SDK iterates **all** pages transparently (`fetchAllPages[T]`), requesting
`size=10000` per page and stopping on `last`, an empty page, or
`page >= totalPages-1`. List methods return the concatenated content; new list
operations must reuse this helper.

### 2.6 Error contract

Every response with status ≥ 400 becomes a `*APIError`. Three body shapes exist and are
all folded into the same struct:

1. **Standard** (`ApiErrorModel`): `{"code": "...", "message": "...", "errors": [...]}` —
   `errors[]` carries per-field validation messages for bean-validation failures.
2. **Framework fallback** (malformed request the controller never saw):
   `{"timestamp", "status", "error", "message", "path"}`.
3. **IdP-native OAuth2** (token endpoints): `{"error", "error_description"}` — folded
   into `Message` when no message is present.

Non-JSON bodies fall back to the HTTP status text. Callers branch on `APIError.Code`
(the `ErrCode*` constants), never on `Message`. The server's `ApiErrorCode` enum is
exactly these 19 values:

| Code | HTTP | Meaning |
|---|---|---|
| `BAD_REQUEST` | 400 | invalid parameter/enum, bad input, plugin failure, upload too large |
| `WRONG_CREDENTIALS` | 401 | bad login credentials (also locked accounts, deliberately indistinguishable) |
| `INVALID_TOKEN` | 401 | malformed or expired token |
| `DEACTIVATED_TOKEN` | 401 | token revoked/deactivated |
| `INVALID_SIGNATURE` | 401 | JWT signature verification failed |
| `UNAUTHORIZED` | 401 | authentication required/failed (raised outside the controller advice) |
| `FORBIDDEN_ACCESS` | 403 | authenticated but policy denies |
| `FORBIDDEN_OPERATION` | 403 | operation not allowed on this resource (e.g. use-attribute gate) |
| `TOO_MANY_RESULTS` | 403 | query would exceed the permitted result count |
| `DISABLED_ACCOUNT` | 403 | account disabled or not yet verified |
| `EMAIL_VERIFICATION_TOKEN_INVALID` | 400/401 | invalid or expired e-mail verification token |
| `RESOURCE_NOT_FOUND` | 404 | entity does not exist **or is outside the caller's universe** |
| `CONFLICT` | 409 | duplicate/conflicting resource |
| `INVALID_MULTIPART` | 415 | malformed multipart request / wrong content type |
| `QUOTA_EXCEEDED` | 429 | universe quota exhausted |
| `INTERNAL_SERVER_ERROR` | 500 | unhandled error, device/provider failure |
| `KEY_LIFECYCLE` | 500 | invalid lifecycle transition or lifecycle-related failure |
| `NOT_IMPLEMENTED` | 501 | operation not supported by this provider/plugin |
| `INTERNAL_KEY_ATTRIBUTES_DIFFERENT` | **260** | internal key attributes differ from the external key (attach/import consistency check) |

Additional response-shape rules:

- **HTTP 260** is a non-standard, *success-shaped* status that always carries an
  error-shaped `ApiErrorModel` body. `do()` folds it into the error path globally
  (`StatusCode >= 400 || StatusCode == 260`), so it surfaces as a `*APIError` with
  `StatusCode` 260 and code `INTERNAL_KEY_ATTRIBUTES_DIFFERENT` (defaulted even on
  an empty body) on every endpoint — operations need no special handling. Callers
  of import/attach should know the operation may nonetheless have taken effect.
- **HTTP 202** with body `{"code": "APPROVAL_REQUIRED", ...}` is returned on
  deployments with 4-eyes approval configured — but only for universe and CA
  mutations, which are out of this SDK's scope (§7). No in-scope endpoint can
  return it. If that ever changes, extend the 260 branch in `do()` with a
  distinct-outcome path (approval pending is not a failure).
- **`X-Correlation-Id`** (servers ≥ 4.3.0.4): `WithCorrelationID(ctx, id)` sends a
  caller-chosen id (reused on the 401 replay); the server always echoes one on the
  response — generated when absent — and `newAPIError` captures it into
  `APIError.CorrelationID`. Older servers ignore the header harmlessly.

## 3. Key model and lifecycle

Object hierarchy: **universe** (tenant) → **crypto provider** (PKCS#11/HSM, remote KMS,
AWS KMS, EJBCA, SOFT) → **vslot** (virtual slot: the container keys live in, bound to
one provider and one universe) → **key** → **key values** (individual pieces of
material: secret/public/private/certificate, possibly wrapped). Users belong to one
universe; resources outside it read as 404, not 403.

**Lifecycle** — one-way, never reversible:

```
PROVISIONED → ACTIVE → DEACTIVATED → DESTROYED → DELETED
```

- `PROVISIONED`: created with `validFrom` in the future; no crypto operations yet.
- `ACTIVE`: all operations permitted (subject to use attributes).
- `DEACTIVATED`: only non-data-protection operations — verify and decrypt of existing
  data still work (while `enabled`); sign and encrypt do not.
- `DESTROYED`: material deleted, metadata kept.
- `DELETED`: material **and** metadata removed immediately; never persisted.

Each state carries an `enabled` flag that further gates operations. `validFrom` /
`validTo` cause **automatic** transitions server-side, so a cached state can be stale.
State changes go through `POST /keys/{id}/state` with `{"state": ..., "enabled": ...}`;
**there is no HTTP DELETE for keys** — deletion is posting the `DELETED` state, which
is exactly what `DeleteKey` does. Violations surface as `KEY_LIFECYCLE` (500) or
`FORBIDDEN_OPERATION` (403).

**Persistence** (`persistence` field): `INTERNAL` (material lives in the provider,
e.g. HSM), `EXTERNAL` (stored wrapped in the KMS database), `NONE` (not stored — the
creation response is the **only** chance to capture the material).

**Key algorithms** (`alg` on creation): `AES128` `AES192` `AES256` · `DES3` ·
`RSA1024` `RSA2048` `RSA3072` `RSA4096` `RSA8192` · `secp256r1` `secp384r1`
`secp521r1` `secp256k1` `brainpoolP256t1` `brainpoolP384t1` · `generic256`
`generic512` (HMAC secrets) · `plain` · `MLDSA44` `MLDSA65` `MLDSA87` (post-quantum,
provider-dependent). No Ed25519/X25519, no ML-KEM.

**Use attributes**: eight PKCS#11-style booleans (`extractable`, `sign`, `verify`,
`encrypt`, `decrypt`, `wrap`, `unwrap`, `derive`). Operations are rejected when the
flag is off. When present in a request, all eight are serialized (no `omitempty`) so
explicit `false` reaches the server.

**Capability discovery**: `GET /keys/{id}` returns `supportedAlgorithms[]`
(`CryptoAlgorithmModel`): the identifiers valid for that key, the usages they apply
to, and — via `params` — the `attributes` keys each algorithm consumes (e.g. `iv`).
Prefer this over hard-coding algorithm/key compatibility client-side.

**Rotation**: `POST /keys/{id}/rotate` deactivates the old key and creates a
successor; the response is an **empty 200**, so the new key id must be re-queried.
The chain is visible in `keyLinks[]`/`rotated` on the key detail; aliases provide a
stable handle across rotations. `RotateKey` implements the re-query: it reads the
key's links before and after the rotation and returns the single new link; when
zero or several new links appear (link direction is deployment-observed, not
guaranteed), it returns an error matching `ErrSuccessorUnknown` while the rotation
itself has still happened.

## 4. Current SDK surface

### Client construction

```go
func NewClient(opts ...Option) *Client        // no network I/O
func (c *Client) Connect(ctx context.Context) error
func (c *Client) Logout(ctx context.Context) error
```

| Option | Effect |
|---|---|
| `WithBaseURL(url)` | Deployment root **without** `/api`; trailing slash trimmed. Default: INCERT UAT. |
| `WithUsernameAndPassword(u, p)` | Credentials for the password grant / self-managed login. |
| `WithClientSecret(s)` | OAuth2 client secret for confidential clients; consumed only by the `provider: OTHER` backend. |
| `WithTimeout(d)` | Overall timeout of the SDK-managed HTTP client (default 10 s — raise for synchronous key generation on slow HSMs). |
| `WithTLSCACert(file)` | PEM trust anchors for the SDK-managed client, replacing the system roots; also governs the identity provider's token requests. Read at construction; load failures surface from `Connect`. |
| `WithTLSCAPath(dir)` | Directory walked recursively for PEM trust anchors; files without certificates are skipped; combines with `WithTLSCACert`. |
| `WithTLSClientCert(certFile, keyFile)` | Client certificate and private key for mutual TLS; both required. |
| `WithTLSServerName(name)` | Server name for SNI and certificate verification. |
| `WithTLSConfig(cfg)` | Base `*tls.Config` (cloned); the other `WithTLS*` options layer onto it. |
| `WithHTTPClient(hc)` | Custom `*http.Client`; wins over `WithTimeout` and every `WithTLS*` option (one warning is logged). |
| `WithTLSSkipVerify()` | Disable TLS verification (development only; warns and is ignored with a custom client; warns when combined with CA material or a server name). |
| `WithLogger(l)` | `*slog.Logger` for diagnostics; silent by default. |

Per-call: `WithCorrelationID(ctx, id)` returns a context that makes every request
issued with it carry the `X-Correlation-Id` header (§2.6).

### Operations

| Method | HTTP call | Media type | Returns |
|---|---|---|---|
| `Connect(ctx)` | `GET /configs/auth` → token endpoint → `GET /vslots` | — | — |
| `Logout(ctx)` | `POST /auth/token/logout` (self-managed) or local drop (OAuth2) | `application/json` | — |
| `GetVSlots(ctx)` | `GET /vslots` (all pages) | — | `[]Vslot` |
| `GetKeys(ctx, vslotID)` | = `FindKeys` with empty filter | — | `[]KeySearchResult` |
| `FindKeys(ctx, vslotID, filter)` | `GET /keys?vslotId=…&sort=creationDate,desc[&name=…][&id=…][&alias=…][&type=…][&alg=…][&persistence=…][&state=…][&enabled=…]` (all pages) | — | `[]KeySearchResult` |
| `GetKey(ctx, keyID)` | `GET /keys/{id}` | — | `KeyDetail` |
| `CreateKey(ctx, vslotID, KeyData)` | `POST /vslots/{id}/p/kg?async=false` | `application/kms.key+json` | `KeyDataResponse{ID, Values}` |
| `DeleteKey(ctx, keyID)` | `POST /keys/{id}/state` body `{"state":"DELETED"}` | `application/json` | — |
| `Crypto(ctx, op, keyID, CryptoRequest)` | `POST /keys/{id}/p/encrypt\|decrypt` | `application/kms.encrypt+json` | `[]byte` (the `data` field) |
| `Sign(ctx, keyID, SignRequest)` | `POST /keys/{id}/p/sign` | `application/kms.sign+json` | `[]byte` signature |
| `Verify(ctx, keyID, SignRequest)` | `POST /keys/{id}/p/verify` | `application/kms.sign+json` | `bool` |
| `SetKeyState(ctx, keyID, state, enabled)` | `POST /keys/{id}/state` | `application/json` | — (empty 200) |
| `RotateKey(ctx, keyID)` | `GET /keys/{id}` → `POST /keys/{id}/rotate` (empty 200) → `GET /keys/{id}` | `application/json` | successor `uuid.UUID` |
| `FindKeyAliases(ctx, filter)` | `GET /keys/aliases?sort=creationDate,desc[&id=…][&key.id=…]` (all pages) | — | `[]KeyAlias` |
| `CreateKeyAlias(ctx, keyID)` | `POST /keys/{id}/alias` (no body) | — | `KeyAlias` |
| `MoveKeyAlias(ctx, aliasID, fromKeyID, toKeyID)` | `POST /keys/{to}/alias` body `{"aliasId","keyId":<from>}` | `application/json` | `KeyAlias` |
| `ExportKey(ctx, keyID, values)` | `POST /keys/{id}/p/export` | `application/kms.key+json` | `KeyDataResponse` |
| `EditKey(ctx, keyID, useAttributes)` | `POST /keys/{id}/p/edit` body `{"useAttributes":…}` | `application/kms.key+json` | `KeyDataResponse` |
| `ImportKey(ctx, vslotID, KeyData)` | `POST /vslots/{id}/p/ki?async=false` | `application/kms.key+json` | `KeyDataResponse` |
| `ImportKeyValues(ctx, keyID, values)` | `POST /keys/{id}/p/ki` | `application/kms.key+json` | `KeyDataResponse` |
| `AttachKey(ctx, vslotID, KeyData)` | `POST /vslots/{id}/p/ka?async=false` | `application/kms.key+json` | `KeyDataResponse` |
| `DeriveKey(ctx, keyID, DeriveRequest)` | `POST /keys/{id}/p/derive` | `application/kms.derive+json` | `KeyDataResponse` |
| `TransportKey(ctx, keyID, targetVslotID)` | `POST /keys/{id}/transport` body `{"vslotId":…}` | `application/kms.transport+json` | `KeyDataResponse` |
| `SignSOD(ctx, keyID, SignSODRequest)` | `POST /keys/{id}/p/sign` | `application/kms.sign-sod+json` | `[]byte` SOD |
| `SignTimestamp(ctx, keyID, SignTimestampRequest)` | `POST /keys/{id}/p/sign` | `application/kms.sign-timestamp+json` | `[]byte` DER `TimeStampResp` |
| `SignPDF(ctx, keyID, pdf)` | `POST /keys/{id}/p/sign` body `{"data":…}` | `application/kms.sign+pdf` | `[]byte` signed PDF |
| `GenerateCertificate(ctx, keyID, CertificateRequest)` | `POST /keys/{id}/p/certgen` | `application/kms.certificate+json` | `[]byte` DER certificate |
| `GenerateCSR(ctx, keyID, CertificateRequest)` | `POST /keys/{id}/p/csrgen` | `application/kms.certificate+json` | `[]byte` DER CSR |
| `UpdateCertificate(ctx, keyID, cert, storeInDB)` | `POST /keys/{id}/p/certupdate` body `{"encoded":…[,"storeInDb":true]}` | `application/kms.certificate+json` | `[]byte` |
| `GetKeyAsyncProcesses(ctx)` / `GetVSlotAsyncProcesses(ctx)` | `GET /keys\|vslots/async-processes` (all pages) | — | `[]AsyncProcess` |
| `GetKeyAsyncProcess(ctx, id)` / `GetVSlotAsyncProcess(ctx, id)` | `GET /keys\|vslots/async-processes/{id}` | — | `AsyncProcess` |
| `DeleteKeyAsyncProcess(ctx, id)` / `DeleteVSlotAsyncProcess(ctx, id)` | `DELETE /keys\|vslots/async-processes/{id}` → 204 | — | — |

### Behavioral invariants

These are load-bearing; the test suite asserts them and changes to them are breaking:

- Calling any authenticated method before `Connect` fails fast with
  `"client not connected: call Connect first"` — no HTTP request is made.
- `Crypto` rejects any operation other than `OperationEncrypt`/`OperationDecrypt`
  client-side, without an HTTP call. Other operations use different media types and
  get their own methods.
- `Verify` reports a wrong signature as `(false, nil)` — the server never fails the
  HTTP call for an invalid signature (`{"valid": false}`); an error return means the
  operation itself failed. The signature under test travels in
  `SignRequest.Attributes.Signature`.
- On 401, authenticated requests are replayed exactly once with a fresh token; there is
  no other retry of any kind.
- `Logout` on a never-connected client is a no-op; after `Logout`, the next call
  re-authenticates with the stored credentials.
- List methods iterate every server page; callers always see the complete result.
- Every non-2xx response yields a `*APIError`; transport errors never do. HTTP 260
  also yields a `*APIError` despite being success-shaped (§2.6).
- `SetKeyState` sends both `state` and `enabled` (explicit `false` reaches the
  server); `DeleteKey` keeps its historical body of exactly `{"state":"DELETED"}`.
- `RotateKey` distinguishes outcomes: a failed rotation returns the server's
  `*APIError` (and skips the post-read); a successful rotation whose successor
  cannot be identified returns an error matching `ErrSuccessorUnknown`.
- `EditKey` always serializes all eight use-attribute flags, and nothing else —
  the server processes only `useAttributes` on `p/edit`.
- The SDK provides no polling loop for async processes; callers own the cadence
  (records are retained ~24 h by default — poll promptly).

## 5. Algorithm identifiers

Identifiers are passed in the `algorithm` field of operation requests. Per key, the
authoritative list is `KeyDetail.SupportedAlgorithms`; the registry below is the full
set implemented by the server's PKCS#11 provider (currently the only provider plugin).

### Encrypt / decrypt (`Crypto`)

| Identifier | `attributes` |
|---|---|
| `AES_ECB` | — |
| `AES_CBC` | `iv` (16 bytes, required) |
| `AES_CBC_PKCS7` | `iv` (16 bytes, required); optional `multi` (batching, §7) |
| `AES_CTR` | `iv` (≤ 16 bytes); optional `counter` (integer — when set, `iv` ≤ 12 bytes) |
| `AES_GCM` | `iv` (12-byte nonce, required); optional `aad` |
| `CKM_DES3_ECB` | — |
| `CKM_DES3_CBC` / `CKM_DES3_CBC_PAD` | `iv` (8 bytes) |
| `RSA_PKCS1` / `RSA_PKCS1_NoPadding` | — |
| `RSA_OAEP_SHA1` / `_SHA224` / `_SHA256` / `_SHA384` / `_SHA512` | optional `label` (base64) |

Binary attribute values (`iv`, `aad`, `label`) are base64 strings — pass `[]byte` in
`CryptoRequest.Attributes` and JSON encoding does the rest.

### Sign / verify (`Sign`, `Verify`)

| Identifier | Notes |
|---|---|
| `RSA_PKCS_RAW` | caller-prepared digest in `data` |
| `RSA_PKCS_SHA1` / `_SHA256` / `_SHA384` / `_SHA512` | |
| `RSA_PKCS-PSS_RAW` | `hashAlg`/`mgf`/`saltLength` as numeric PKCS#11 constants (§2.4) |
| `RSA_PKCS-PSS_SHA1` / `_SHA256` / `_SHA384` / `_SHA512` | |
| `EC` | raw ECDSA over a caller-prepared digest |
| `EC_SHA1` / `_SHA224` / `_SHA256` / `_SHA384` / `_SHA512` | |
| `HMAC_SHA1` / `_SHA256` / `_SHA384` / `_SHA512` | key alg `generic256`/`generic512` |
| `AES_CMAC` | |
| `MLDSA_44` / `MLDSA_65` / `MLDSA_87` | post-quantum, provider-dependent |
| `CSR_SIGN` | |

There is no SHA-224 RSA variant and no MD5 signature identifier. Mind the spelling
split: the *key* algorithm is `MLDSA44` (no underscore), the *signature* identifier is
`MLDSA_44`.

### Derive (`DeriveKey`)

`DERIVE_KCV` · `DERIVE_SHA1` / `_SHA256` / `_SHA384` / `_SHA512` · `DERIVE_AES_ECB`
(`data` required) · `DERIVE_AES_CBC` (`data` and `iv` required). Derivation creates a
new key; the response is a `KeyDataResponseModel`. `DeriveRequest.Attributes` is
`map[string]string` — the wire model maps to strings (`label`, `data`, `iv`), unlike
the encrypt/sign attribute maps.

## 6. Coverage map and roadmap

What the server offers in the SDK's scope versus what is implemented. Each roadmap item
lists the endpoint, media type, and the design notes that constrain it. New operations
follow the established pattern: a typed request model in its own `*_request.go` file
where warranted, a thin method over `do()`, and table-driven httptest coverage.

| Capability | Endpoint(s) | Status |
|---|---|---|
| Auth: self-managed + Keycloak + generic OIDC password grant | `/configs/auth`, `/auth/token*`, IdP token endpoints | ✅ implemented |
| Vslot listing | `GET /vslots` | ✅ implemented |
| Key search/read/create/delete | `GET /keys`, `GET /keys/{id}`, `POST /vslots/{v}/p/kg`, `POST /keys/{id}/state` | ✅ implemented |
| Key state management, rotation, aliases | `POST /keys/{id}/state`, `POST /keys/{id}/rotate`, `GET /keys/aliases`, `POST /keys/{id}/alias` | ✅ implemented |
| Export, import, attach, edit | `POST /keys/{id}/p/{export,ki,edit}`, `POST /vslots/{v}/p/{ki,ka}` | ✅ implemented |
| Derive, transport | `POST /keys/{id}/p/derive`, `POST /keys/{id}/transport` | ✅ implemented |
| Encrypt/decrypt, sign/verify, sign flavors | `POST /keys/{id}/p/{encrypt,decrypt,sign,verify}` (all four sign media types) | ✅ implemented |
| Certificate operations | `POST /keys/{id}/p/{certgen,csrgen,certupdate}` | ✅ implemented |
| Async process queries | `GET\|DELETE /keys\|vslots/async-processes[/{id}]` | ✅ implemented |
| Correlation ids | `X-Correlation-Id` header + `APIError.CorrelationID` | ✅ implemented |
| Everything below | | ⬜ roadmap |

Roadmap:

1. **Async triggering** — the `/p/*` operations accept `?async=true` (the SDK
   hard-codes `async=false` where the parameter is required), but the response
   shape of an async-triggered call (status, body, process-id field) is
   undocumented and must be verified against a live server before methods can
   return it. When it lands: separate `*Async` method variants (the return type
   changes — never a mode flag), plus
   `GET /keys|vslots/async-processes/{id}/download-output`
   (`application/octet-stream`; needs raw-body support in `do()`). Relevant for
   slow HSM generation (RSA4096 can exceed the 10 s default timeout even
   synchronously).
2. **Large payloads / batching** — multipart alternative for `/p/*` (part
   `request` = the JSON envelope without `data`, part `data` = raw bytes; response
   may be `application/octet-stream`); multi-data batching via
   `attributes.multi = true` with `data` = base64 of
   `{"multiData":{"1":"<b64>", ...}}` (doubly encoded).
3. **Auth extensions** — a device-authorization grant for interactive CLIs
   (documented for Keycloak, client `kms-p11`); server-side logout for OAuth2
   providers if a flow is ever documented (`logoutEndpoint` exists in discovery
   but is unused).
4. **Remaining key-management surface** — `PUT /keys/{id}` (metadata-only update,
   empty 200; distinct from `p/edit`, which propagates into the provider), vslot
   create/update, `GET /configs/capabilities`, and the `labels` map filter on
   `GET /keys` (query syntax unverified).

Items needing live-server verification (not blocking, noted where relevant):
the async-trigger response shape; the direction of `keyLinks` after a rotation
(`RotateKey` handles both via `ErrSuccessorUnknown`); the transport media type
(§2.3 caveat); `scope=openid` acceptance on audience-scoped Auth0 password
grants.

Design cautions for all future work:

- **Never add blanket retry or prefetch logic.** Parts of the wider API (PKI
  revocation, universe cancel/restore) are `GET` requests **with side effects**; a
  retrying or prefetching layer would be destructive there. Keep the 401-replay as the
  only retry.
- Content-Type dispatch means one endpoint ≠ one method: model each schema separately.
- Anything touching universe/CA mutations must handle 202 `APPROVAL_REQUIRED` (§2.6).

## 7. Out of scope

The following server areas are deliberately outside this SDK's scope. If that changes,
they warrant their own service types rather than growth of `Client`:

- **PKI** — profiles, CAs, certificate issuance/revocation, CRL management.
- **Administration** — universes, users, policies (IAM-style ALLOW/DENY statements
  with filters), quotas, providers, PKCS#11/KMS devices, TLS trust, audit logs, KPIs,
  4-eyes approval management.
- **Public service endpoints** — RFC 3161 TSA (`/tsr`), JWKS, public CRL
  distribution, actuator health.
- **KMIP** — the server speaks KMIP 1.2 natively over mTLS on its own port; a KMIP
  integration is configuration, not an API-client concern.
