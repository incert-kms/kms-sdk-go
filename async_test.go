package kmssdk

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestClient_GetKeyAsyncProcesses(t *testing.T) {
	processID := uuid.New()
	keyID := uuid.New()
	var pages []string
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/keys/async-processes" {
			t.Errorf("path = %s, want /api/keys/async-processes", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("size") != "10000" {
			t.Errorf("size = %q, want 10000", q.Get("size"))
		}
		if q.Get("sort") != "creationDate,desc" {
			t.Errorf("sort = %q, want creationDate,desc", q.Get("sort"))
		}
		page := q.Get("page")
		pages = append(pages, page)
		json.NewEncoder(w).Encode(pagedResponse[AsyncProcess]{
			Content:    []AsyncProcess{{ID: processID, KeyID: keyID, Status: AsyncProcessFinished, Process: "encrypt"}},
			TotalPages: 2,
			Last:       page == "1",
		})
	})

	got, err := client.GetKeyAsyncProcesses(context.Background())
	if err != nil {
		t.Fatalf("GetKeyAsyncProcesses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (one per page)", len(got))
	}
	if got[0].ID != processID || got[0].KeyID != keyID || got[0].Status != AsyncProcessFinished {
		t.Errorf("process = %+v", got[0])
	}
	if want := []string{"0", "1"}; !equalStrings(pages, want) {
		t.Errorf("requested pages = %v, want %v", pages, want)
	}
}

func TestClient_GetKeyAsyncProcess(t *testing.T) {
	processID := uuid.New()
	keyID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/keys/async-processes/" + processID.String()
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id":                          processID,
			"status":                      "FINISHED",
			"keyId":                       keyID,
			"process":                     "encrypt",
			"processJsonRequest":          `{"algorithm":"AES_GCM"}`,
			"processJsonResponse":         `{"data":"yv4="}`,
			"processResponseEmbeddedInDb": true,
			"failures":                    1,
			"lastFailureReason":           "device busy",
		})
	})

	got, err := client.GetKeyAsyncProcess(context.Background(), processID)
	if err != nil {
		t.Fatalf("GetKeyAsyncProcess: %v", err)
	}
	if got.ID != processID || got.KeyID != keyID || got.Status != AsyncProcessFinished {
		t.Errorf("process = %+v", got)
	}
	if got.ProcessJSONResponse != `{"data":"yv4="}` || !got.ProcessResponseEmbeddedInDB {
		t.Errorf("response fields not decoded: %+v", got)
	}
	if got.Failures != 1 || got.LastFailureReason != "device busy" {
		t.Errorf("failure fields not decoded: %+v", got)
	}
}

func TestClient_GetVSlotAsyncProcesses(t *testing.T) {
	processID := uuid.New()
	vslotID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/vslots/async-processes" {
			t.Errorf("path = %s, want /api/vslots/async-processes", r.URL.Path)
		}
		json.NewEncoder(w).Encode(pagedResponse[AsyncProcess]{
			Content:    []AsyncProcess{{ID: processID, VslotID: vslotID, Status: AsyncProcessInProgress, Process: "kg"}},
			TotalPages: 1,
			Last:       true,
		})
	})

	got, err := client.GetVSlotAsyncProcesses(context.Background())
	if err != nil {
		t.Fatalf("GetVSlotAsyncProcesses: %v", err)
	}
	if len(got) != 1 || got[0].VslotID != vslotID || got[0].KeyID != uuid.Nil {
		t.Errorf("processes = %+v, want one vslot-scoped record", got)
	}
}

func TestClient_GetVSlotAsyncProcess(t *testing.T) {
	processID := uuid.New()
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/vslots/async-processes/" + processID.String()
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		json.NewEncoder(w).Encode(AsyncProcess{ID: processID, Status: AsyncProcessError})
	})

	got, err := client.GetVSlotAsyncProcess(context.Background(), processID)
	if err != nil {
		t.Fatalf("GetVSlotAsyncProcess: %v", err)
	}
	if got.ID != processID || got.Status != AsyncProcessError {
		t.Errorf("process = %+v", got)
	}
}

func TestClient_DeleteAsyncProcess(t *testing.T) {
	processID := uuid.New()

	cases := []struct {
		name     string
		call     func(c *Client) error
		wantPath string
	}{
		{
			name:     "key-scoped",
			call:     func(c *Client) error { return c.DeleteKeyAsyncProcess(context.Background(), processID) },
			wantPath: "/api/keys/async-processes/" + processID.String(),
		},
		{
			name:     "vslot-scoped",
			call:     func(c *Client) error { return c.DeleteVSlotAsyncProcess(context.Background(), processID) },
			wantPath: "/api/vslots/async-processes/" + processID.String(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("method = %s, want DELETE", r.Method)
				}
				if r.URL.Path != tc.wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, tc.wantPath)
				}
				w.WriteHeader(http.StatusNoContent)
			})

			if err := tc.call(client); err != nil {
				t.Fatalf("delete async process: %v", err)
			}
		})
	}
}
