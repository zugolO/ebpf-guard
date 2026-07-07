//go:build rego

package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── buildTLS ──────────────────────────────────────────────────────────────────

func TestBuildTLS_AutoGenerate(t *testing.T) {
	srv := &Server{
		config: Config{TLSAutoGenerate: true},
		logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}

	cfg, err := srv.buildTLS()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}

func TestBuildTLS_MissingCertAndKey(t *testing.T) {
	srv := &Server{
		config: Config{}, // no auto-generate, no cert/key paths
		logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}

	cfg, err := srv.buildTLS()
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "tls_cert_file and tls_key_file are required")
}

func TestBuildTLS_MissingKeyOnly(t *testing.T) {
	srv := &Server{
		config: Config{TLSCertFile: "/some/cert.pem"}, // key file left empty
		logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}

	cfg, err := srv.buildTLS()
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestBuildTLS_LoadFromFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	certPEM, keyPEM := generateTestCertPEM(t)
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	srv := &Server{
		config: Config{TLSCertFile: certPath, TLSKeyFile: keyPath},
		logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}

	cfg, err := srv.buildTLS()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}

func TestBuildTLS_LoadFromFiles_BadPaths(t *testing.T) {
	srv := &Server{
		config: Config{TLSCertFile: "/nonexistent/cert.pem", TLSKeyFile: "/nonexistent/key.pem"},
		logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}

	cfg, err := srv.buildTLS()
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "load TLS key pair")
}

// generateTestCertPEM generates a fresh self-signed ECDSA P-256 cert/key pair
// as PEM bytes, independent of autoGenerateTLS, so it can be written to disk
// and loaded back through buildTLS's tls.LoadX509KeyPair file-based path.
func generateTestCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// ── autoGenerateTLS ───────────────────────────────────────────────────────────

func TestAutoGenerateTLS_CertProperties(t *testing.T) {
	srv := &Server{logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	cfg, err := srv.autoGenerateTLS()
	require.NoError(t, err)
	require.Len(t, cfg.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)

	leaf := cfg.Certificates[0]
	require.NotEmpty(t, leaf.Certificate)
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)

	assert.Equal(t, "ebpf-guard-admission", parsed.Subject.CommonName)
	assert.True(t, parsed.NotBefore.Before(time.Now()), "NotBefore should be in the past")
	assert.True(t, parsed.NotAfter.After(time.Now().Add(24*time.Hour)), "NotAfter should be far in the future")
	assert.Contains(t, parsed.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

// ── Start / Shutdown ──────────────────────────────────────────────────────────

// TestServer_StartShutdown boots the real HTTPS server on an ephemeral port
// (auto-generated TLS cert) and verifies it accepts a TLS connection and then
// shuts down cleanly.
func TestServer_StartShutdown(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Mode:            "warn",
		WebhookPath:     "/admission",
		RegoDir:         dir,
		TLSAutoGenerate: true,
		BindAddress:     "127.0.0.1:0",
	}
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	// Start binds s.config.BindAddress directly via http.Server.ListenAndServeTLS,
	// which does not report back the actual ephemeral port. To deterministically
	// exercise Start/Shutdown without racing on port assignment, pre-bind an
	// ephemeral listener ourselves, close it to free the port, and immediately
	// reuse the discovered port for BindAddress. This keeps the test hermetic
	// while avoiding a fixed port number.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	srv.config.BindAddress = addr

	require.NoError(t, srv.Start(context.Background()))

	// Poll until the server is accepting TLS connections (background goroutine
	// startup is async).
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, dialErr := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only, self-signed cert
		if dialErr == nil {
			conn.Close()
			lastErr = nil
			break
		}
		lastErr = dialErr
		time.Sleep(20 * time.Millisecond)
	}
	require.NoError(t, lastErr, "expected TLS server to accept connections")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assert.NoError(t, srv.Shutdown(ctx))

	// A second Shutdown call must remain a safe no-op-ish (http.Server.Shutdown
	// tolerates repeated calls).
	assert.NoError(t, srv.Shutdown(ctx))
}

// TestServer_Shutdown_NilInnerServer verifies Shutdown is a no-op when Start
// was never called (s.server is nil).
func TestServer_Shutdown_NilInnerServer(t *testing.T) {
	srv := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assert.NoError(t, srv.Shutdown(ctx))
}

// TestServer_Start_BadTLSConfig verifies Start surfaces buildTLS errors
// without starting a listener.
func TestServer_Start_BadTLSConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{RegoDir: dir} // no TLS cert/key, no auto-generate
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	err = srv.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "build TLS")
	assert.Nil(t, srv.server)
}

// ── newAdmissionEngine ────────────────────────────────────────────────────────

func TestNewAdmissionEngine_InvalidRego(t *testing.T) {
	dir := t.TempDir()
	bad := `
package ebpf_guard.admission

deny[msg] {
	this is not valid rego syntax !!!
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.rego"), []byte(bad), 0o600))

	engine, err := newAdmissionEngine(dir)
	assert.Error(t, err)
	assert.Nil(t, engine)
	assert.Contains(t, err.Error(), "compile admission policies")
}

func TestNewAdmissionEngine_ValidRego(t *testing.T) {
	dir := t.TempDir()
	good := `
package ebpf_guard.admission

deny[msg] {
	input.request.namespace == "forbidden"
	msg := "no"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "good.rego"), []byte(good), 0o600))

	engine, err := newAdmissionEngine(dir)
	require.NoError(t, err)
	require.NotNil(t, engine)
	require.NotNil(t, engine.prepared)

	denials, warnings, err := engine.evaluate(context.Background(), map[string]interface{}{
		"request": map[string]interface{}{"namespace": "forbidden"},
	})
	require.NoError(t, err)
	assert.Contains(t, denials, "no")
	assert.Empty(t, warnings)
}

func TestNewAdmissionEngine_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	engine, err := newAdmissionEngine(dir)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Nil(t, engine.prepared)
}

func TestNewAdmissionEngine_NonExistentDir(t *testing.T) {
	engine, err := newAdmissionEngine("/does/not/exist/at/all")
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Nil(t, engine.prepared)
}

// ── extractStringSet ──────────────────────────────────────────────────────────

func TestExtractStringSet_SliceForm(t *testing.T) {
	result := extractStringSet([]interface{}{"a", "b", 1, "c"})
	assert.ElementsMatch(t, []string{"a", "b", "c"}, result)
}

func TestExtractStringSet_MapForm(t *testing.T) {
	// OPA sometimes serializes Rego sets as a map with string keys and empty
	// struct-ish values when decoded through generic JSON.
	result := extractStringSet(map[string]interface{}{
		"denied-a": struct{}{},
		"denied-b": struct{}{},
	})
	assert.ElementsMatch(t, []string{"denied-a", "denied-b"}, result)
}

func TestExtractStringSet_Nil(t *testing.T) {
	assert.Nil(t, extractStringSet(nil))
}

func TestExtractStringSet_UnknownType(t *testing.T) {
	assert.Nil(t, extractStringSet(42))
}

// ── HandleHealth via HandleAdmission counters (unhealthy) ────────────────────

func TestHandleHealth_UnhealthyAfterServerError(t *testing.T) {
	srv := newTestServer(t)
	srv.healthy.Store(false)

	req, _ := http.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.HandleHealth(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
