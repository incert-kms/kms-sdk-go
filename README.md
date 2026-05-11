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

    client := kmssdk.NewClient(ctx,
        kmssdk.WithBaseURL("https://kms-uat.incert.lu/kms/api"),
        kmssdk.WithUsernameAndPassword(os.Getenv("KMS_USERNAME"), os.Getenv("KMS_PASSWORD")),
        kmssdk.WithLogger(logger),
    )

    if err := client.Connect(ctx); err != nil {
        panic(err)
    }

    // Create a new AES 256 key in a vslot
    vslotID := uuid.MustParse(os.Getenv("KMS_VSLOT_ID"))
    key, err := client.CreateKey(ctx, kmssdk.KeyDetail{
        Alg:         "AES256",
        Name:        "example-key",
        Persistence: "EXTERNAL",
    }, vslotID)
    if err != nil {
        panic(err)
    }
    fmt.Println("AES KEY:", key.ID)
}
```

See [examples](./examples) for more.

## Features

The SDK exposes the operations needed to manage and use keys through the Keys&More REST API:

- Authentication
    - OAuth2 with Keycloak (auto-discovered from the server's `/configs/auth` endpoint)
    - Token caching and refresh handled transparently
- Vslots
    - List vslots
- Keys lifecycle
    - Create keys
    - Read keys (by ID or by listing/filtering within a vslot)
    - Delete keys (state transition to `DELETED`)
- Cryptographic operations
    - Encrypt / Decrypt data

## Configuration

`NewClient` accepts the following options:

| Option | Description |
| --- | --- |
| `WithBaseURL(url)` | Override the default API base URL. |
| `WithUsernameAndPassword(user, pass)` | Credentials used for the Keycloak password grant. |
| `WithHTTPClient(hc)` | Supply a custom `*http.Client`. |
| `WithTLSSkipVerify()` | Disable TLS verification (development only). |
| `WithLogger(l)` | Supply a `*slog.Logger`; without it the SDK is silent. |

## Error handling

API errors are returned as `*kmssdk.APIError` and can be inspected with `errors.As`:

```go
if err := client.Connect(ctx); err != nil {
    var apiErr *kmssdk.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
    } else {
        fmt.Printf("unexpected error: %v\n", err)
    }
}
```

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](./LICENSE).
