package kmssdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// okHandler answers every request with an empty JSON object.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("{}"))
})

// writeFile writes content to dir/name, creating parent directories, and
// returns the path.
func writeFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// writeCertPEM writes a DER certificate as a PEM file named name inside dir
// and returns its path.
func writeCertPEM(t *testing.T, dir, name string, der []byte) string {
	t.Helper()
	return writeFile(t, dir, name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// startTLSServer starts a TLS server with httptest's self-signed certificate
// (issued for example.com and the loopback addresses) and writes that
// certificate to a PEM file, returned as caFile.
func startTLSServer(t *testing.T, handler http.Handler) (srv *httptest.Server, caFile string) {
	t.Helper()
	srv = httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv, writeCertPEM(t, t.TempDir(), "ca.pem", srv.Certificate().Raw)
}

// writeClientCert generates a self-signed client certificate, writes it and
// its private key as PEM files inside dir, and returns both paths plus the
// parsed certificate so a server can be told to trust it.
func writeClientCert(t *testing.T, dir string) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kms-sdk-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPath = writeFile(t, dir, "client-key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return writeCertPEM(t, dir, "client.pem", der), keyPath, cert
}

// logBuffer returns a logger writing text records into the returned buffer.
func logBuffer() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// unauthGet issues one unauthenticated request through the client's real
// request path, so the transport is exercised without a token source.
func unauthGet(c *Client) error {
	return c.do(context.Background(), http.MethodGet, "/x", nil, false, nil)
}

// managedTransport returns the client's transport as *http.Transport.
func managedTransport(t *testing.T, c *Client) *http.Transport {
	t.Helper()
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.httpClient.Transport)
	}
	return tr
}

func TestNewClient_tlsSkipVerify(t *testing.T) {
	c := NewClient(WithTLSSkipVerify(), WithTimeout(3*time.Second))
	if c.tlsErr != nil {
		t.Fatalf("tlsErr = %v, want nil", c.tlsErr)
	}
	tr := managedTransport(t, c)
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
	def := http.DefaultTransport.(*http.Transport)
	if tr.Proxy == nil {
		t.Error("Proxy = nil, want the default transport's proxy function")
	}
	if got, want := tr.TLSHandshakeTimeout, def.TLSHandshakeTimeout; got != want {
		t.Errorf("TLSHandshakeTimeout = %s, want %s", got, want)
	}
	if got, want := tr.MaxIdleConns, def.MaxIdleConns; got != want {
		t.Errorf("MaxIdleConns = %d, want %d", got, want)
	}
	if got, want := tr.ForceAttemptHTTP2, def.ForceAttemptHTTP2; got != want {
		t.Errorf("ForceAttemptHTTP2 = %v, want %v", got, want)
	}
	if got, want := c.httpClient.Timeout, 3*time.Second; got != want {
		t.Errorf("Timeout = %s, want %s", got, want)
	}

	srv, _ := startTLSServer(t, okHandler)
	t.Run("default client rejects an untrusted server", func(t *testing.T) {
		if err := unauthGet(NewClient(WithBaseURL(srv.URL))); err == nil {
			t.Error("request succeeded, want a certificate verification error")
		}
	})
	t.Run("skip verify accepts it", func(t *testing.T) {
		if err := unauthGet(NewClient(WithBaseURL(srv.URL), WithTLSSkipVerify())); err != nil {
			t.Errorf("request failed: %v", err)
		}
	})
}

func TestNewClient_tlsCACert(t *testing.T) {
	srv, caFile := startTLSServer(t, okHandler)
	c := NewClient(WithBaseURL(srv.URL), WithTLSCACert(caFile))
	if c.tlsErr != nil {
		t.Fatalf("tlsErr = %v, want nil", c.tlsErr)
	}
	if err := unauthGet(c); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	cfg := managedTransport(t, c).TLSClientConfig
	if cfg.RootCAs == nil {
		t.Error("RootCAs = nil, want the configured pool")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true, want false")
	}
}

func TestNewClient_tlsCAPath(t *testing.T) {
	srv := httptest.NewTLSServer(okHandler)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	writeCertPEM(t, dir, filepath.Join("sub", "nested", "kms-ca.pem"), srv.Certificate().Raw)
	writeFile(t, dir, "README", []byte("not a certificate"))
	writeFile(t, dir, filepath.Join("sub", "notes.txt"), []byte("still not a certificate"))

	c := NewClient(WithBaseURL(srv.URL), WithTLSCAPath(dir))
	if c.tlsErr != nil {
		t.Fatalf("tlsErr = %v, want nil", c.tlsErr)
	}
	if err := unauthGet(c); err != nil {
		t.Errorf("request failed: %v", err)
	}
}

func TestNewClient_tlsClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, clientCert := writeClientCert(t, dir)
	pool := x509.NewCertPool()
	pool.AddCert(clientCert)
	srv := httptest.NewUnstartedServer(okHandler)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := writeCertPEM(t, dir, "server-ca.pem", srv.Certificate().Raw)

	// Without a client certificate the server must refuse us, otherwise the
	// positive case below proves nothing.
	if err := unauthGet(NewClient(WithBaseURL(srv.URL), WithTLSCACert(caFile))); err == nil {
		t.Fatal("request without a client certificate succeeded, want a rejection")
	}

	c := NewClient(WithBaseURL(srv.URL), WithTLSCACert(caFile), WithTLSClientCert(certPath, keyPath))
	if c.tlsErr != nil {
		t.Fatalf("tlsErr = %v, want nil", c.tlsErr)
	}
	if err := unauthGet(c); err != nil {
		t.Fatalf("request with client certificate failed: %v", err)
	}
	if got, want := len(managedTransport(t, c).TLSClientConfig.Certificates), 1; got != want {
		t.Errorf("len(Certificates) = %d, want %d", got, want)
	}
}

func TestNewClient_tlsServerName(t *testing.T) {
	srv, caFile := startTLSServer(t, okHandler)
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "example.com", wantErr: false},
		{name: "kms.invalid", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(WithBaseURL(srv.URL), WithTLSCACert(caFile), WithTLSServerName(tc.name))
			if got := managedTransport(t, c).TLSClientConfig.ServerName; got != tc.name {
				t.Errorf("ServerName = %q, want %q", got, tc.name)
			}
			err := unauthGet(c)
			if (err != nil) != tc.wantErr {
				t.Errorf("request error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConnect_tlsConfigurationError(t *testing.T) {
	dir := t.TempDir()
	bogus := writeFile(t, dir, "bogus.pem", []byte("not a certificate"))
	noCerts := filepath.Join(dir, "no-certs")
	writeFile(t, noCerts, "README", []byte("not a certificate"))

	tests := []struct {
		name     string
		opt      Option
		wantErr  string
		notExist bool
	}{
		{"missing ca file", WithTLSCACert(filepath.Join(dir, "missing.pem")), "reading ca certificate file", true},
		{"ca file without certificates", WithTLSCACert(bogus), "no certificates found in ca certificate file", false},
		{"missing ca path", WithTLSCAPath(filepath.Join(dir, "missing")), "reading ca certificate directory", true},
		{"ca path without certificates", WithTLSCAPath(noCerts), "no certificates found in ca certificate directory", false},
		{"client cert without key", WithTLSClientCert(bogus, ""), "must be set together", false},
		{"unparsable client cert", WithTLSClientCert(bogus, bogus), "loading client certificate", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			t.Cleanup(srv.Close)

			c := NewClient(WithBaseURL(srv.URL), tc.opt)
			if c.tlsErr == nil {
				t.Fatal("tlsErr = nil, want the load error")
			}
			err := c.Connect(context.Background())
			if err == nil {
				t.Fatal("Connect succeeded, want an error")
			}
			if !strings.HasPrefix(err.Error(), "tls configuration: ") {
				t.Errorf("Connect error = %q, want the tls configuration prefix", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Connect error = %q, want it to contain %q", err, tc.wantErr)
			}
			if tc.notExist && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("errors.Is(err, fs.ErrNotExist) = false, want true: %v", err)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("server hits = %d, want 0", got)
			}
			if _, ok := c.httpClient.Transport.(failingTransport); !ok {
				t.Errorf("transport = %T, want failingTransport", c.httpClient.Transport)
			}
			if err := unauthGet(c); !errors.Is(err, c.tlsErr) {
				t.Errorf("unauthenticated request error = %v, want it to wrap %v", err, c.tlsErr)
			}
		})
	}
}

func TestNewClient_tlsOptionsIgnoredWithCustomClient(t *testing.T) {
	logger, buf := logBuffer()
	hc := &http.Client{}
	c := NewClient(WithHTTPClient(hc), WithLogger(logger),
		WithTLSCACert("/no/such/ca.pem"), WithTLSServerName("kms.example.com"), WithTLSSkipVerify())
	if c.httpClient != hc {
		t.Error("custom http client not installed")
	}
	if hc.Transport != nil {
		t.Error("custom client was modified")
	}
	if c.tlsErr != nil {
		t.Errorf("tlsErr = %v, want nil since nothing should be loaded", c.tlsErr)
	}
	const want = "TLS options are ignored when WithHTTPClient supplies a custom client"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log = %q, want it to contain %q", buf.String(), want)
	}
	if got := strings.Count(buf.String(), "level=WARN"); got != 1 {
		t.Errorf("warnings = %d, want 1: %q", got, buf.String())
	}
}

func TestNewClient_tlsSkipVerifyWithTrustMaterialWarns(t *testing.T) {
	_, caFile := startTLSServer(t, okHandler)

	logger, buf := logBuffer()
	NewClient(WithLogger(logger), WithTLSSkipVerify(), WithTLSCACert(caFile))
	const want = "WithTLSSkipVerify disables certificate verification"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log = %q, want it to contain %q", buf.String(), want)
	}

	logger, buf = logBuffer()
	NewClient(WithLogger(logger), WithTLSSkipVerify())
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("unexpected warning without trust material: %q", buf.String())
	}
}

func TestConnect_overTLS(t *testing.T) {
	var tokenHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/configs/auth", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(Config{
			Type: AuthenticationTypeOAuth2,
			OAuth2: &OAuth2Config{
				Provider: OAuth2ProviderKeycloak,
				Keycloak: &OAuth2KeycloakConfig{URL: "/idp", Realm: "myrealm", ClientID: "myclient"},
			},
		})
	})
	mux.HandleFunc("POST /idp/realms/myrealm/protocol/openid-connect/token",
		keycloakTokenHandler(t, "myclient", &tokenHits))
	mux.HandleFunc("GET /api/vslots", func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer fresh-token"; got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		json.NewEncoder(w).Encode(pagedResponse[Vslot]{TotalPages: 1, Last: true})
	})
	srv, caFile := startTLSServer(t, mux)

	t.Run("without ca", func(t *testing.T) {
		c := NewClient(WithBaseURL(srv.URL), WithUsernameAndPassword("u", "p"))
		err := c.Connect(context.Background())
		if err == nil || !strings.Contains(err.Error(), "getting config") {
			t.Errorf("Connect error = %v, want a getting config failure", err)
		}
		if got := tokenHits.Load(); got != 0 {
			t.Errorf("token hits = %d, want 0", got)
		}
	})
	t.Run("with ca", func(t *testing.T) {
		c := NewClient(WithBaseURL(srv.URL), WithUsernameAndPassword("u", "p"), WithTLSCACert(caFile))
		if err := c.Connect(context.Background()); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		if got := tokenHits.Load(); got != 1 {
			t.Errorf("token hits = %d, want 1", got)
		}
	})
}

func TestWithTLSConfig(t *testing.T) {
	srv, caFile := startTLSServer(t, okHandler)
	certPath, keyPath, clientCert := writeClientCert(t, t.TempDir())

	t.Run("caller config not mutated", func(t *testing.T) {
		cfg := &tls.Config{RootCAs: x509.NewCertPool(), Certificates: make([]tls.Certificate, 0, 4)}
		snapshot := cfg.RootCAs.Clone()
		c := NewClient(WithTLSConfig(cfg), WithTLSCACert(caFile), WithTLSClientCert(certPath, keyPath),
			WithTLSServerName("example.com"), WithTLSSkipVerify())
		if c.tlsErr != nil {
			t.Fatalf("tlsErr = %v, want nil", c.tlsErr)
		}
		if cfg.ServerName != "" {
			t.Errorf("caller ServerName = %q, want empty", cfg.ServerName)
		}
		if cfg.InsecureSkipVerify {
			t.Error("caller InsecureSkipVerify = true, want false")
		}
		if !cfg.RootCAs.Equal(snapshot) {
			t.Error("caller RootCAs was modified")
		}
		if got := len(cfg.Certificates); got != 0 {
			t.Errorf("caller Certificates = %d, want 0", got)
		}

		got := managedTransport(t, c).TLSClientConfig
		if got.ServerName != "example.com" {
			t.Errorf("ServerName = %q, want example.com", got.ServerName)
		}
		if !got.InsecureSkipVerify {
			t.Error("InsecureSkipVerify = false, want true")
		}
		if n := len(got.Certificates); n != 1 {
			t.Errorf("len(Certificates) = %d, want 1", n)
		}
		if got.RootCAs.Equal(cfg.RootCAs) {
			t.Error("transport RootCAs equals the caller's pool, want the extended clone")
		}
	})

	t.Run("root cas extend the supplied pool", func(t *testing.T) {
		base := x509.NewCertPool()
		base.AddCert(srv.Certificate())
		// The CA option points at unrelated material; the base anchors must survive.
		c := NewClient(WithBaseURL(srv.URL), WithTLSConfig(&tls.Config{RootCAs: base}), WithTLSCACert(certPath))
		if err := unauthGet(c); err != nil {
			t.Errorf("base anchors were not retained: %v", err)
		}

		other := x509.NewCertPool()
		other.AddCert(clientCert)
		c = NewClient(WithBaseURL(srv.URL), WithTLSConfig(&tls.Config{RootCAs: other}), WithTLSCACert(caFile))
		if err := unauthGet(c); err != nil {
			t.Errorf("CA option was not applied on top of the base pool: %v", err)
		}
	})

	t.Run("nil config is ignored", func(t *testing.T) {
		c := NewClient(WithTLSConfig(nil))
		if c.httpClient.Transport != nil {
			t.Errorf("transport = %T, want nil (default client)", c.httpClient.Transport)
		}
		if c.tlsErr != nil {
			t.Errorf("tlsErr = %v, want nil", c.tlsErr)
		}
	})

	t.Run("base insecure flag respected", func(t *testing.T) {
		c := NewClient(WithBaseURL(srv.URL), WithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err := unauthGet(c); err != nil {
			t.Errorf("request failed: %v", err)
		}
	})
}
