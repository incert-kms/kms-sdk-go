package kmssdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestClient_SetKeyState(t *testing.T) {
	keyID := uuid.New()

	cases := []struct {
		name    string
		state   string
		enabled bool
	}{
		{"activate enabled", KeyStateActive, true},
		{"deactivate disabled", KeyStateDeactivated, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				wantPath := "/api/keys/" + keyID.String() + "/state"
				if r.URL.Path != wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
				}
				if got, want := r.Header.Get("Content-Type"), "application/json"; got != want {
					t.Errorf("Content-Type = %q, want %q", got, want)
				}
				var req map[string]any
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decoding request body: %v", err)
				}
				if got, want := req["state"], tc.state; got != want {
					t.Errorf("state = %v, want %v", got, want)
				}
				// enabled must always be serialized, including explicit false.
				enabled, ok := req["enabled"]
				if !ok {
					t.Error("request body missing 'enabled' field")
				}
				if enabled != tc.enabled {
					t.Errorf("enabled = %v, want %v", enabled, tc.enabled)
				}
				w.WriteHeader(http.StatusOK)
			})

			if err := client.SetKeyState(context.Background(), keyID, tc.state, tc.enabled); err != nil {
				t.Fatalf("SetKeyState: %v", err)
			}
		})
	}
}

func TestClient_RotateKey(t *testing.T) {
	keyID := uuid.New()
	predecessorID := uuid.New()
	successorID := uuid.New()

	cases := []struct {
		name        string
		linksBefore []uuid.UUID
		linksAfter  []uuid.UUID
		want        uuid.UUID
		wantErr     error
	}{
		{"first rotation", nil, []uuid.UUID{successorID}, successorID, nil},
		{"chained rotation", []uuid.UUID{predecessorID}, []uuid.UUID{predecessorID, successorID}, successorID, nil},
		{"no new link", []uuid.UUID{predecessorID}, []uuid.UUID{predecessorID}, uuid.Nil, ErrSuccessorUnknown},
		{"two new links", nil, []uuid.UUID{predecessorID, successorID}, uuid.Nil, ErrSuccessorUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gets, rotates atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/keys/"+keyID.String(), func(w http.ResponseWriter, r *http.Request) {
				links := tc.linksBefore
				if gets.Add(1) > 1 {
					links = tc.linksAfter
				}
				json.NewEncoder(w).Encode(KeyDetail{ID: keyID, KeyLinks: links, Rotated: rotates.Load() > 0})
			})
			mux.HandleFunc("POST /api/keys/"+keyID.String()+"/rotate", func(w http.ResponseWriter, r *http.Request) {
				rotates.Add(1)
				body, _ := io.ReadAll(r.Body)
				if len(body) != 0 {
					t.Errorf("rotate request body = %q, want empty", body)
				}
				if ct := r.Header.Get("Content-Type"); ct != "" {
					t.Errorf("Content-Type = %q, want none", ct)
				}
				w.WriteHeader(http.StatusOK)
			})
			client, _ := testClient(t, mux.ServeHTTP)

			got, err := client.RotateKey(context.Background(), keyID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("RotateKey: %v", err)
			}
			if got != tc.want {
				t.Errorf("successor = %s, want %s", got, tc.want)
			}
			if rotates.Load() != 1 {
				t.Errorf("rotate hit %d times, want 1", rotates.Load())
			}
		})
	}
}

func TestClient_RotateKey_rotateFailureSkipsSecondRead(t *testing.T) {
	keyID := uuid.New()
	var gets atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/keys/"+keyID.String(), func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		json.NewEncoder(w).Encode(KeyDetail{ID: keyID})
	})
	mux.HandleFunc("POST /api/keys/"+keyID.String()+"/rotate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"code": ErrCodeKeyLifecycle, "message": "cannot rotate"})
	})
	client, _ := testClient(t, mux.ServeHTTP)

	_, err := client.RotateKey(context.Background(), keyID)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != ErrCodeKeyLifecycle {
		t.Fatalf("err = %v, want *APIError with code KEY_LIFECYCLE", err)
	}
	if errors.Is(err, ErrSuccessorUnknown) {
		t.Error("a failed rotation must not report ErrSuccessorUnknown")
	}
	if gets.Load() != 1 {
		t.Errorf("GET key hit %d times, want 1 (no re-read after a failed rotate)", gets.Load())
	}
}

func TestClient_FindKeyAliases(t *testing.T) {
	aliasID := uuid.New()
	keyID := uuid.New()
	var pages []string
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/keys/aliases" {
			t.Errorf("path = %s, want /api/keys/aliases", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("size") != "10000" {
			t.Errorf("size = %q, want 10000", q.Get("size"))
		}
		if q.Get("sort") != "creationDate,desc" {
			t.Errorf("sort = %q, want creationDate,desc", q.Get("sort"))
		}
		if q.Get("key.id") != keyID.String() {
			t.Errorf("key.id = %q, want %s", q.Get("key.id"), keyID)
		}
		if q.Get("id") != "" {
			t.Errorf("id should be absent, got %q", q.Get("id"))
		}
		page := q.Get("page")
		pages = append(pages, page)
		// Raw JSON so the "key" wire-field name is asserted, not round-tripped.
		json.NewEncoder(w).Encode(map[string]any{
			"content":    []map[string]any{{"id": aliasID, "key": keyID, "universe": "main"}},
			"totalPages": 2,
			"last":       page == "1",
		})
	})

	got, err := client.FindKeyAliases(context.Background(), KeyAliasFilter{KeyID: keyID})
	if err != nil {
		t.Fatalf("FindKeyAliases: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (one per page)", len(got))
	}
	if got[0].ID != aliasID || got[0].KeyID != keyID || got[0].Universe != "main" {
		t.Errorf("alias = %+v, want id/key/universe decoded", got[0])
	}
	if want := []string{"0", "1"}; !equalStrings(pages, want) {
		t.Errorf("requested pages = %v, want %v", pages, want)
	}
}

func TestClient_CreateKeyAlias(t *testing.T) {
	keyID := uuid.New()
	aliasID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/api/keys/" + keyID.String() + "/alias"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("request body = %q, want empty (empty body creates a new alias)", body)
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			t.Errorf("Content-Type = %q, want none", ct)
		}
		json.NewEncoder(w).Encode(map[string]any{"id": aliasID, "key": keyID})
	})

	got, err := client.CreateKeyAlias(context.Background(), keyID)
	if err != nil {
		t.Fatalf("CreateKeyAlias: %v", err)
	}
	if got.ID != aliasID || got.KeyID != keyID {
		t.Errorf("alias = %+v, want ID %s pointing at %s", got, aliasID, keyID)
	}
}

func TestClient_MoveKeyAlias(t *testing.T) {
	aliasID := uuid.New()
	fromKeyID := uuid.New()
	toKeyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/keys/" + toKeyID.String() + "/alias"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s (the new target key)", r.URL.Path, wantPath)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if len(req) != 2 {
			t.Errorf("request body = %v, want exactly aliasId and keyId", req)
		}
		if req["aliasId"] != aliasID.String() {
			t.Errorf("aliasId = %v, want %s", req["aliasId"], aliasID)
		}
		// keyId in the body is the key the alias currently references.
		if req["keyId"] != fromKeyID.String() {
			t.Errorf("keyId = %v, want %s", req["keyId"], fromKeyID)
		}
		json.NewEncoder(w).Encode(map[string]any{"id": aliasID, "key": toKeyID})
	})

	got, err := client.MoveKeyAlias(context.Background(), aliasID, fromKeyID, toKeyID)
	if err != nil {
		t.Fatalf("MoveKeyAlias: %v", err)
	}
	if got.ID != aliasID || got.KeyID != toKeyID {
		t.Errorf("alias = %+v, want ID %s pointing at %s", got, aliasID, toKeyID)
	}
}
