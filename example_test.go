package kmssdk_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	kmssdk "github.com/incert-kms/kms-sdk-go"
)

func ExampleNewClient() {
	ctx := context.Background()

	client := kmssdk.NewClient(
		kmssdk.WithBaseURL("https://kms.example.com/kms/api"),
		kmssdk.WithUsernameAndPassword(os.Getenv("KMS_USERNAME"), os.Getenv("KMS_PASSWORD")),
	)
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	vslots, err := client.GetVSlots(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, vslot := range vslots {
		fmt.Println(vslot.ID, vslot.ProviderName)
	}
}

func ExampleClient_CreateKey() {
	ctx := context.Background()
	client := kmssdk.NewClient(
		kmssdk.WithUsernameAndPassword(os.Getenv("KMS_USERNAME"), os.Getenv("KMS_PASSWORD")),
	)
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	vslotID := uuid.MustParse(os.Getenv("KMS_VSLOT_ID"))
	created, err := client.CreateKey(ctx, vslotID, kmssdk.KeyData{
		Name:        "example-key",
		Alg:         "AES256",
		Persistence: kmssdk.PersistenceExternal,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("new key:", created.ID)
}

func ExampleClient_Crypto() {
	ctx := context.Background()
	client := kmssdk.NewClient(
		kmssdk.WithUsernameAndPassword(os.Getenv("KMS_USERNAME"), os.Getenv("KMS_PASSWORD")),
	)
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	keyID := uuid.MustParse(os.Getenv("KMS_KEY_ID"))
	iv := []byte("0123456789ab") // 12-byte GCM nonce; never reuse with the same key

	ciphertext, err := client.Crypto(ctx, kmssdk.OperationEncrypt, keyID, kmssdk.CryptoRequest{
		Data:       []byte("secret message"),
		Algorithm:  "AES_GCM",
		Attributes: map[string]any{"iv": iv},
	})
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := client.Crypto(ctx, kmssdk.OperationDecrypt, keyID, kmssdk.CryptoRequest{
		Data:       ciphertext,
		Algorithm:  "AES_GCM",
		Attributes: map[string]any{"iv": iv},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext))
}

func ExampleAPIError() {
	ctx := context.Background()
	client := kmssdk.NewClient(
		kmssdk.WithUsernameAndPassword(os.Getenv("KMS_USERNAME"), os.Getenv("KMS_PASSWORD")),
	)

	if err := client.Connect(ctx); err != nil {
		var apiErr *kmssdk.APIError
		switch {
		case errors.As(err, &apiErr) && apiErr.Code == kmssdk.ErrCodeWrongCredentials:
			fmt.Println("check KMS_USERNAME / KMS_PASSWORD")
		case errors.As(err, &apiErr):
			fmt.Printf("API error %d (%s): %s\n", apiErr.StatusCode, apiErr.Code, apiErr.Message)
		default:
			fmt.Printf("transport error: %v\n", err)
		}
	}
}
