package kmssdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func selfManagedLoginHandler(t *testing.T, logins *atomic.Int32) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if logins != nil {
			logins.Add(1)
		}
		if got, want := r.Header.Get("Content-Type"), "application/json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding login body: %v", err)
		}
		if req.Username != "u" || req.Password != "p" {
			t.Errorf("login body = %+v, want u/p", req)
		}
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:      "sm-token",
			RefreshToken:     "sm-refresh",
			ExpiresIn:        300,
			RefreshExpiresIn: 3600,
		})
	}
}

func TestConnect_selfManaged(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("GET /api/configs/auth", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Config{Type: AuthenticationTypeSelfManaged})
	})
	mux.HandleFunc("POST /api/auth/token", selfManagedLoginHandler(t, nil))
	mux.HandleFunc("GET /api/vslots", func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer sm-token"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		json.NewEncoder(w).Encode(pagedResponse[Vslot]{TotalPages: 1, Last: true})
	})

	client := NewClient(WithBaseURL(srv.URL), WithUsernameAndPassword("u", "p"))
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestSelfManaged_refreshKeepsRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/token/refresh" {
			t.Errorf("path = %s, want /auth/token/refresh", r.URL.Path)
		}
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding refresh body: %v", err)
		}
		if req.RefreshToken != "login-refresh" {
			t.Errorf("refresh_token = %q, want login-refresh", req.RefreshToken)
		}
		// AccessTokenRefreshedModel: no new refresh token is issued.
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "new-access", ExpiresIn: 300})
	}))
	t.Cleanup(srv.Close)

	s := newSelfManagedAuth(srv.URL, srv.Client(), "u", "p", nil)
	s.refreshToken = "login-refresh"
	s.refreshTokenExpiry = time.Now().Add(time.Hour)

	token, err := s.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if token != "new-access" {
		t.Errorf("token = %q, want new-access", token)
	}
	if s.refreshToken != "login-refresh" {
		t.Errorf("refresh token = %q, want the login one retained", s.refreshToken)
	}
}

func TestSelfManaged_refreshRejectedFallsBackToLogin(t *testing.T) {
	var logins atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("POST /auth/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"code": ErrCodeDeactivatedToken, "message": "token deactivated"})
	})
	mux.HandleFunc("POST /auth/token", selfManagedLoginHandler(t, &logins))

	s := newSelfManagedAuth(srv.URL, srv.Client(), "u", "p", nil)
	s.refreshToken = "deactivated-refresh"
	s.refreshTokenExpiry = time.Now().Add(time.Hour)

	token, err := s.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if token != "sm-token" {
		t.Errorf("token = %q, want sm-token", token)
	}
	if logins.Load() != 1 {
		t.Errorf("logins = %d, want 1", logins.Load())
	}
	if s.refreshToken != "sm-refresh" {
		t.Errorf("refresh token = %q, want the fresh login one", s.refreshToken)
	}
}

func TestSelfManaged_logout(t *testing.T) {
	var logins, logouts atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("POST /auth/token/logout", func(w http.ResponseWriter, r *http.Request) {
		logouts.Add(1)
		var req struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding logout body: %v", err)
		}
		if req.AccessToken != "cached-access" || req.RefreshToken != "cached-refresh" {
			t.Errorf("logout body = %+v, want both cached tokens", req)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /auth/token", selfManagedLoginHandler(t, &logins))

	client := NewClient(WithBaseURL(srv.URL), WithUsernameAndPassword("u", "p"))
	s := newSelfManagedAuth(srv.URL, client.httpClient, "u", "p", nil)
	s.accessToken = "cached-access"
	s.accessTokenExpiry = time.Now().Add(time.Hour)
	s.refreshToken = "cached-refresh"
	s.refreshTokenExpiry = time.Now().Add(time.Hour)
	client.tokenSource = s

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if logouts.Load() != 1 {
		t.Errorf("logouts = %d, want 1", logouts.Load())
	}

	// The cache is cleared: the next token request performs a fresh login.
	token, err := s.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken after logout: %v", err)
	}
	if token != "sm-token" || logins.Load() != 1 {
		t.Errorf("token = %q (logins = %d), want fresh login", token, logins.Load())
	}
}

func TestClient_selfManagedReauthenticatesOnceOn401(t *testing.T) {
	var protectedHits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("POST /auth/token", selfManagedLoginHandler(t, nil))
	mux.HandleFunc("GET /api/protected", func(w http.ResponseWriter, r *http.Request) {
		protectedHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer sm-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"code": ErrCodeDeactivatedToken, "message": "deactivated"})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	client := NewClient(WithBaseURL(srv.URL), WithUsernameAndPassword("u", "p"))
	source := newSelfManagedAuth(srv.URL, client.httpClient, "u", "p", nil)
	// Seed a token that is still valid locally but deactivated server-side.
	source.accessToken = "stale-token"
	source.accessTokenExpiry = time.Now().Add(time.Hour)
	client.tokenSource = source

	if err := client.do(context.Background(), http.MethodGet, "/protected", nil, true, nil); err != nil {
		t.Fatalf("expected replay to succeed, got %v", err)
	}
	if got := protectedHits.Load(); got != 2 {
		t.Errorf("protected endpoint hit %d times, want 2 (401 then replay)", got)
	}
}
