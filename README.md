# kms-sdk-go

[![Go Reference](https://pkg.go.dev/badge/github.com/incert-kms/kms-sdk-go.svg)](https://pkg.go.dev/github.com/incert-kms/kms-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/incert-kms/kms-sdk-go)](https://goreportcard.com/report/github.com/incert-kms/kms-sdk-go)
[![Tests](https://github.com/incert-kms/kms-sdk-go/actions/workflows/test.yml/badge.svg)](https://github.com/incert-kms/kms-sdk-go/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-Apache%202.0-red.svg?style=flat)](./LICENSE)

The Go SDK to interact with the [INCERT Keys&More](https://www.incert.lu) KMS service.

> **NOTE:** THIS PROJECT IS CURRENTLY UNDER DEVELOPMENT AND SUBJECT TO BREAKING CHANGES.

## How to use

Add it to your project by running

```bash
go get github.com/incert-kms/kms-sdk-go@latest
```

Then connect to your KMS service and start using it:

```go
package main

import (
    "context"
    "fmt"
    "log/slog"
    "os"

    "github.com/google/uuid"
    kmssdk "github.com/incert-kms/kms-sdk-go"
)

func main() {
    ctx := context.Background()

    logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))

    client := kmssdk.NewClient(
        kmssdk.WithBaseURL("https://kms.example.com/kms"),
        kmssdk.WithUsernameAndPassword(os.Getenv("KMS_USERNAME"), os.Getenv("KMS_PASSWORD")),
        kmssdk.WithLogger(logger),
    )

    if err := client.Connect(ctx); err != nil {
        panic(err)
    }

    // Create a new AES 256 key in a vslot
    vslotID := uuid.MustParse(os.Getenv("KMS_VSLOT_ID"))
    created, err := client.CreateKey(ctx, vslotID, kmssdk.KeyData{
        Alg:         "AES256",
        Name:        "example-key",
        Persistence: kmssdk.PersistenceExternal,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println("AES KEY:", created.ID)
}
```

See [examples](./examples) and the [package documentation](https://pkg.go.dev/github.com/incert-kms/kms-sdk-go) for more.

## Features

The SDK exposes the operations needed to manage and use keys through the Keys&More REST API:

- Authentication
    - Mode auto-discovered from the server's `/configs/auth` endpoint
    - Self-managed (`SELF_MANAGED`): login, token refresh and logout against the Keys&More TOKEN API
    - OAuth2 with Keycloak (URL, realm and client id from discovery, password grant)
    - Token caching and refresh handled transparently; on a 401 the request is replayed once with a fresh token
    - `Logout` invalidates tokens (server-side on self-managed deployments)
- Vslots
    - List vslots (paged responses iterated transparently)
- Keys lifecycle
    - Create keys (returns the new key id and, for `persistence: NONE`, the generated material)
    - Read keys (by ID or by listing/filtering within a vslot)
    - Delete keys (permanent removal via the `DELETED` lifecycle state)
- Cryptographic operations
    - Encrypt / Decrypt data with algorithm-specific attributes (`iv`, `counter`, `aad`, `label`, ...)
    - Sign / Verify with the full signature registry (RSA PKCS#1/PSS, ECDSA, HMAC, CMAC, ML-DSA); verify reports validity as a boolean, PSS-raw parameters travel as numeric PKCS#11 codes

The client is safe for concurrent use by multiple goroutines once `Connect` has returned.

## Configuration

`NewClient` accepts the following options:

| Option | Description |
| --- | --- |
| `WithBaseURL(url)` | Override the default base URL of the deployment, e.g. `https://kms.example.com/kms` — without the `/api` prefix, which is appended internally (the default points at INCERT's UAT environment). |
| `WithUsernameAndPassword(user, pass)` | Credentials used for the Keycloak password grant. |
| `WithTimeout(d)` | Overall HTTP timeout of the SDK-managed client (default 10s). |
| `WithHTTPClient(hc)` | Supply a custom `*http.Client`; takes precedence over `WithTimeout` and `WithTLSSkipVerify`. |
| `WithTLSSkipVerify()` | Disable TLS verification (development only). |
| `WithLogger(l)` | Supply a `*slog.Logger`; without it the SDK is silent. |

## Error handling

API errors are returned as `*kmssdk.APIError` and can be inspected with `errors.As`.
Branch on the server error code (`ErrCode*` constants) rather than on the message:

```go
if err := client.Connect(ctx); err != nil {
    var apiErr *kmssdk.APIError
    switch {
    case errors.As(err, &apiErr) && apiErr.Code == kmssdk.ErrCodeWrongCredentials:
        fmt.Println("check your username/password")
    case errors.As(err, &apiErr):
        fmt.Printf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
    default:
        fmt.Printf("transport error: %v\n", err) // connection failure, timeout, ...
    }
}
```

Network-level failures (connection errors, timeouts) are not `APIError` values; they wrap
the underlying transport error, so `errors.Is(err, context.DeadlineExceeded)` and
`os.IsTimeout(err)` keep working.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](./LICENSE).
