// Command example exercises the SDK end-to-end against a real deployment:
// connect, create an AES key, encrypt/decrypt a message, and delete the key.
//
// Configuration comes from the environment:
//
//	KMS_BASE_URL  deployment base URL, e.g. https://kms.example.com/kms
//	              (the /api prefix is appended internally)
//	KMS_USERNAME  username for the Keycloak password grant
//	KMS_PASSWORD  password for the Keycloak password grant
//	KMS_VSLOT_ID  UUID of the vslot to create the test key in
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	kmssdk "github.com/incert-kms/kms-sdk-go"
)

func main() {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	opts := []kmssdk.Option{
		kmssdk.WithUsernameAndPassword(os.Getenv("KMS_USERNAME"), os.Getenv("KMS_PASSWORD")),
		kmssdk.WithLogger(logger),
	}
	if baseURL := os.Getenv("KMS_BASE_URL"); baseURL != "" {
		opts = append(opts, kmssdk.WithBaseURL(baseURL))
	}
	client := kmssdk.NewClient(opts...)

	err := client.Connect(ctx)
	if err != nil {
		var apiErr *kmssdk.APIError
		if errors.As(err, &apiErr) {
			fmt.Printf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
		} else {
			fmt.Printf("unexpected error: %v\n", err)
		}
		os.Exit(1)
	}

	vslotID, err := uuid.Parse(os.Getenv("KMS_VSLOT_ID"))
	if err != nil {
		fmt.Printf("invalid KMS_VSLOT_ID: %v\n", err)
		os.Exit(1)
	}

	created, err := client.CreateKey(ctx, vslotID, kmssdk.KeyData{
		Alg:         "AES256",
		Name:        "test-key",
		Persistence: kmssdk.PersistenceExternal,
	})
	if err != nil {
		fmt.Printf("error creating key: %v\n", err)
		os.Exit(1)
	}

	keyRetrieved, err := client.GetKey(ctx, created.ID)
	if err != nil {
		fmt.Printf("error retrieving key: %v\n", err)
		os.Exit(1)
	}
	if keyRetrieved.ID != created.ID {
		fmt.Printf("retrieved key ID does not match created key ID: got %s, want %s", keyRetrieved.ID, created.ID)
		os.Exit(1)
	}

	plaintext := []byte("secret message")
	iv, err := hex.DecodeString("00112233445566778899aabb")
	if err != nil {
		fmt.Printf("error decoding IV: %v\n", err)
		os.Exit(1)
	}

	ciphertext, err := client.Crypto(ctx, kmssdk.OperationEncrypt, created.ID, kmssdk.CryptoRequest{
		Data:       plaintext,
		Algorithm:  "AES_GCM",
		Attributes: map[string]any{"iv": iv},
	})
	if err != nil {
		fmt.Printf("error encrypting: %v\n", err)
		os.Exit(1)
	}

	decrypted, err := client.Crypto(ctx, kmssdk.OperationDecrypt, created.ID, kmssdk.CryptoRequest{
		Data:       ciphertext,
		Algorithm:  "AES_GCM",
		Attributes: map[string]any{"iv": iv},
	})
	if err != nil {
		fmt.Printf("error decrypting: %v\n", err)
		os.Exit(1)
	}

	if !bytes.Equal(decrypted, plaintext) {
		fmt.Printf("decryption mismatch: got %q, want %q\n", decrypted, plaintext)
		os.Exit(1)
	}
	fmt.Println("decryption verified")

	err = client.DeleteKey(ctx, created.ID)
	if err != nil {
		fmt.Printf("error deleting key: %v\n", err)
		os.Exit(1)
	}
}
