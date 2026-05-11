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
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	client := kmssdk.NewClient(
		context.Background(),
		kmssdk.WithTLSSkipVerify(),
		kmssdk.WithUsernameAndPassword("adi", "salam"),
		kmssdk.WithBaseURL("http://localhost:3000/api"),
		kmssdk.WithLogger(logger),
	)

	err := client.Connect(context.Background())
	if err != nil {
		var apiErr *kmssdk.APIError
		if errors.As(err, &apiErr) {
			fmt.Printf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
		} else {
			fmt.Printf("unexpected error: %v\n", err)
		}
		os.Exit(1)
	}

	key := kmssdk.KeyDetail{
		Alg:         "AES256",
		Name:        "test-key",
		Persistence: "EXTERNAL",
	}
	key, err = client.CreateKey(context.Background(), key, uuid.MustParse("a73b7303-ce75-4666-8a3d-e9fb269424fb"))
	if err != nil {
		fmt.Printf("error creating key: %v\n", err)
		os.Exit(1)
	}

	keyRetrieved, err := client.GetKey(context.Background(), key.ID)
	if err != nil {
		fmt.Printf("error retrieving key: %v\n", err)
		os.Exit(1)
	}
	if keyRetrieved.ID != key.ID {
		fmt.Printf("retrieved key ID does not match created key ID: got %s, want %s", keyRetrieved.ID, key.ID)
		os.Exit(1)
	}

	plaintext := []byte("secret message")
	iv, err := hex.DecodeString("00112233445566778899aabb")
	if err != nil {
		fmt.Printf("error decoding IV: %v\n", err)
		os.Exit(1)
	}

	ciphertext, err := client.Crypto(context.Background(), kmssdk.OperationEncrypt, key.ID, kmssdk.CryptoRequest{
		Data:       plaintext,
		Algorithm:  "AES_GCM",
		Attributes: kmssdk.Attributes{IV: iv},
	})
	if err != nil {
		fmt.Printf("error encrypting: %v\n", err)
		os.Exit(1)
	}

	decrypted, err := client.Crypto(context.Background(), kmssdk.OperationDecrypt, key.ID, kmssdk.CryptoRequest{
		Data:       ciphertext,
		Algorithm:  "AES_GCM",
		Attributes: kmssdk.Attributes{IV: iv},
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

	err = client.DeleteKey(context.Background(), key.ID)
	if err != nil {
		fmt.Printf("error deleting key: %v\n", err)
		os.Exit(1)
	}
}
