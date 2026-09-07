package kmssdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCAuth_passwordGrant(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing token form: %v", err)
		}
		gotForm = r.PostForm
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 300})
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid"}, srv.URL+"/oauth/token", srv.Client(), "u", "p", "", nil)
	token, err := o.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if token != "tok" {
		t.Errorf("token = %q, want tok", token)
	}
	for key, want := range map[string]string{
		"grant_type": "password",
		"client_id":  "cid",
		"username":   "u",
		"password":   "p",
		"scope":      "openid",
	} {
		if got := gotForm.Get(key); got != want {
			t.Errorf("form %s = %q, want %q", key, got, want)
		}
	}
	for _, absent := range []string{"audience", "client_secret"} {
		if gotForm.Has(absent) {
			t.Errorf("form must not carry %s when unconfigured, got %q", absent, gotForm.Get(absent))
		}
	}
}

func TestOIDCAuth_audienceAndClientSecret(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing token form: %v", err)
		}
		gotForm = r.PostForm
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok"})
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid", Audience: "KMS"}, srv.URL, srv.Client(), "u", "p", "s3cret", nil)
	if _, err := o.GetToken(context.Background()); err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if got := gotForm.Get("audience"); got != "KMS" {
		t.Errorf("form audience = %q, want KMS", got)
	}
	if got := gotForm.Get("client_secret"); got != "s3cret" {
		t.Errorf("form client_secret = %q, want s3cret", got)
	}
}

func TestOIDCAuth_tokenProperty(t *testing.T) {
	cases := []struct {
		name     string
		property string
		response map[string]any
		want     string
		wantErr  string
	}{
		{"default reads snake_case wire", "", map[string]any{"access_token": "tok"}, "tok", ""},
		{"idToken maps to id_token", "idToken", map[string]any{"id_token": "idt", "access_token": "at"}, "idt", ""},
		{"literal snake_case config", "access_token", map[string]any{"access_token": "tok"}, "tok", ""},
		{"literal camel-case response", "accessToken", map[string]any{"accessToken": "camel"}, "camel", ""},
		{"missing property", "idToken", map[string]any{"access_token": "tok"}, "", "idToken"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(tc.response)
			}))
			t.Cleanup(srv.Close)

			o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid", AccessTokenProperty: tc.property}, srv.URL, srv.Client(), "u", "p", "", nil)
			token, err := o.GetToken(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want mention of %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetToken: %v", err)
			}
			if token != tc.want {
				t.Errorf("token = %q, want %q", token, tc.want)
			}
		})
	}
}

func TestOIDCAuth_cachesTokenWithoutExpiry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok"}) // no expires_in
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid"}, srv.URL, srv.Client(), "u", "p", "", nil)
	for range 2 {
		token, err := o.GetToken(context.Background())
		if err != nil {
			t.Fatalf("GetToken: %v", err)
		}
		if token != "tok" {
			t.Errorf("token = %q, want tok", token)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (no expiry means cache until rejected)", got)
	}
}

func TestOIDCAuth_refreshGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		switch r.PostForm.Get("grant_type") {
		case "password":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "first", "expires_in": 300, "refresh_token": "refresh-1"})
		case "refresh_token":
			if got := r.PostForm.Get("refresh_token"); got != "refresh-1" {
				t.Errorf("refresh_token = %q, want refresh-1", got)
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "second", "expires_in": 300})
		default:
			t.Errorf("unexpected grant_type %q", r.PostForm.Get("grant_type"))
		}
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid"}, srv.URL, srv.Client(), "u", "p", "", nil)
	token, err := o.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken (password): %v", err)
	}
	if token != "first" {
		t.Errorf("token = %q, want first", token)
	}

	// Expire the cached access token; the retained refresh token must be used.
	o.mu.Lock()
	o.accessTokenExpiry = time.Now().Add(-time.Minute)
	o.mu.Unlock()

	token, err = o.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken (refresh): %v", err)
	}
	if token != "second" {
		t.Errorf("token = %q, want second", token)
	}
}

func TestOIDCAuth_refreshFailureFallsBackToPasswordGrant(t *testing.T) {
	var passwordGrants atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		switch r.PostForm.Get("grant_type") {
		case "refresh_token":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Unknown or invalid refresh token"})
		case "password":
			passwordGrants.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh", "expires_in": 300})
		default:
			t.Errorf("unexpected grant_type %q", r.PostForm.Get("grant_type"))
		}
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid"}, srv.URL, srv.Client(), "u", "p", "", nil)
	o.refreshToken = "revoked-refresh"

	token, err := o.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if token != "fresh" {
		t.Errorf("token = %q, want fresh", token)
	}
	if passwordGrants.Load() != 1 {
		t.Errorf("password grants = %d, want 1", passwordGrants.Load())
	}
}

func TestOIDCAuth_refreshServerErrorPropagates(t *testing.T) {
	var passwordGrants atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.PostForm.Get("grant_type") == "password" {
			passwordGrants.Add(1)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid"}, srv.URL, srv.Client(), "u", "p", "", nil)
	o.refreshToken = "some-refresh"

	_, err := o.GetToken(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 500 {
		t.Fatalf("err = %v, want *APIError with status 500", err)
	}
	if passwordGrants.Load() != 0 {
		t.Errorf("password grants = %d, want 0 (5xx must not trigger the fallback)", passwordGrants.Load())
	}
}

func TestOIDCAuth_idpErrorBecomesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Wrong email or password."})
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid"}, srv.URL, srv.Client(), "u", "p", "", nil)
	_, err := o.GetToken(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Message != "invalid_grant (Wrong email or password.)" {
		t.Errorf("Message = %q, want the folded IdP error", apiErr.Message)
	}
}

func TestOIDCAuth_concurrentGetTokenFetchesOnce(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 300})
	}))
	t.Cleanup(srv.Close)

	o := newOIDCAuth(&OAuth2OtherConfig{ClientID: "cid"}, srv.URL, srv.Client(), "u", "p", "", nil)

	const goroutines = 8
	tokens := make([]string, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens[i], errs[i] = o.GetToken(context.Background())
		}()
	}
	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if tokens[i] != "tok" {
			t.Errorf("goroutine %d token = %q", i, tokens[i])
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (no refresh stampede)", got)
	}
}

func TestTokenPropertyCandidates(t *testing.T) {
	cases := []struct {
		property string
		want     []string
	}{
		{"", []string{"accessToken", "access_token"}},
		{"accessToken", []string{"accessToken", "access_token"}},
		{"idToken", []string{"idToken", "id_token"}},
		{"access_token", []string{"access_token"}},
	}
	for _, tc := range cases {
		if got := tokenPropertyCandidates(tc.property); !equalStrings(got, tc.want) {
			t.Errorf("tokenPropertyCandidates(%q) = %v, want %v", tc.property, got, tc.want)
		}
	}
}
