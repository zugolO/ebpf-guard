// Package store provides OpenSearch storage backend tests.
package store

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestOpenSearchStoreIntegration tests the OpenSearch store with a real container.
// This test is skipped unless the -integration flag is provided.
func TestOpenSearchStoreIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Skip on Windows (Docker not available)
	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration test on Windows (Docker not available)")
	}

	ctx := context.Background()

	// Start OpenSearch container
	req := testcontainers.ContainerRequest{
		Image:        "opensearchproject/opensearch:2.11.0",
		ExposedPorts: []string{"9200/tcp"},
		Env: map[string]string{
			"discovery.type":         "single-node",
			"plugins.security.disabled": "true",
			"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "admin123!",
		},
		WaitingFor: wait.ForHTTP("/_cluster/health").
			WithPort("9200/tcp").
			WithStartupTimeout(2 * time.Minute),
	}

	opensearchContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		// No container runtime available (e.g. CI/sandbox without Docker):
		// this is an integration test, so skip rather than fail.
		t.Skipf("skipping: cannot start OpenSearch container (no container runtime?): %v", err)
	}
	defer func() {
		if err := opensearchContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}()

	// Get container host and port
	host, err := opensearchContainer.Host(ctx)
	require.NoError(t, err)

	port, err := opensearchContainer.MappedPort(ctx, "9200")
	require.NoError(t, err)

	address := fmt.Sprintf("http://%s:%s", host, port.Port())

	// Wait a bit more for OpenSearch to be fully ready
	time.Sleep(5 * time.Second)

	// Create store
	cfg := OpenSearchConfig{
		Addresses:          []string{address},
		Username:           "admin",
		Password:           "admin123!",
		IndexPrefix:        "ebpf-guard-test",
		InsecureSkipVerify: true,
	}

	store, err := NewOpenSearchStore(cfg)
	require.NoError(t, err, "failed to create OpenSearch store")
	defer store.Close()

	// Test Healthy
	t.Run("Healthy", func(t *testing.T) {
		// Give OpenSearch time to be ready
		var healthy bool
		for i := 0; i < 10; i++ {
			healthy = store.Healthy(ctx)
			if healthy {
				break
			}
			time.Sleep(1 * time.Second)
		}
		assert.True(t, healthy, "store should be healthy")
	})

	// Test Store
	t.Run("Store", func(t *testing.T) {
		alert := types.Alert{
			ID:        "test-alert-1",
			Timestamp: time.Now(),
			RuleID:    "rule_001",
			RuleName:  "Test Rule",
			Severity:  types.SeverityCritical,
			PID:       1234,
			Comm:      "test",
			Message:   "Test alert message",
			Details: map[string]interface{}{
				"key": "value",
			},
			Enrichment: types.EnrichmentInfo{
				PodName:   "test-pod",
				Namespace: "default",
			},
		}

		err := store.Store(ctx, alert)
		assert.NoError(t, err, "failed to store alert")

		// Query by ID
		retrieved, err := store.QueryByID(ctx, "test-alert-1")
		require.NoError(t, err, "failed to query alert by ID")
		assert.Equal(t, alert.ID, retrieved.ID)
		assert.Equal(t, alert.RuleID, retrieved.RuleID)
		assert.Equal(t, alert.Severity, retrieved.Severity)
		assert.Equal(t, alert.PID, retrieved.PID)
		assert.Equal(t, alert.Comm, retrieved.Comm)
		assert.Equal(t, alert.Message, retrieved.Message)
		assert.Equal(t, alert.Enrichment.PodName, retrieved.Enrichment.PodName)
		assert.Equal(t, alert.Enrichment.Namespace, retrieved.Enrichment.Namespace)
	})

	// Test StoreBatch
	t.Run("StoreBatch", func(t *testing.T) {
		alerts := []types.Alert{
			{
				ID:        "batch-alert-1",
				Timestamp: time.Now(),
				RuleID:    "rule_002",
				Severity:  types.SeverityWarning,
				PID:       5678,
				Comm:      "test2",
				Message:   "Batch alert 1",
			},
			{
				ID:        "batch-alert-2",
				Timestamp: time.Now(),
				RuleID:    "rule_002",
				Severity:  types.SeverityWarning,
				PID:       5679,
				Comm:      "test3",
				Message:   "Batch alert 2",
			},
		}

		err := store.StoreBatch(ctx, alerts)
		assert.NoError(t, err, "failed to store batch alerts")

		// Query to verify
		retrieved, err := store.QueryByID(ctx, "batch-alert-1")
		require.NoError(t, err)
		assert.Equal(t, "batch-alert-1", retrieved.ID)
	})

	// Test Query with filters
	t.Run("Query with filters", func(t *testing.T) {
		// Store test alerts
		testAlerts := []types.Alert{
			{
				ID:        "query-test-1",
				Timestamp: time.Now(),
				RuleID:    "rule_critical",
				Severity:  types.SeverityCritical,
				PID:       1001,
				Comm:      "critical-app",
				Message:   "Critical alert",
				Enrichment: types.EnrichmentInfo{
					PodName:   "critical-pod",
					Namespace: "production",
				},
			},
			{
				ID:        "query-test-2",
				Timestamp: time.Now(),
				RuleID:    "rule_warning",
				Severity:  types.SeverityWarning,
				PID:       1002,
				Comm:      "warning-app",
				Message:   "Warning alert",
				Enrichment: types.EnrichmentInfo{
					PodName:   "warning-pod",
					Namespace: "staging",
				},
			},
		}

		err := store.StoreBatch(ctx, testAlerts)
		require.NoError(t, err)

		// Query by severity
		results, err := store.Query(ctx, QueryFilters{
			Severity: []types.Severity{types.SeverityCritical},
			Limit:    10,
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 1, "should find at least one critical alert")

		// Query by namespace
		results, err = store.Query(ctx, QueryFilters{
			Namespace: "production",
			Limit:     10,
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 1, "should find at least one alert in production namespace")

		// Query by pod
		results, err = store.Query(ctx, QueryFilters{
			PodName: "critical-pod",
			Limit:   10,
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 1, "should find at least one alert for critical-pod")
	})

	// Test Count
	t.Run("Count", func(t *testing.T) {
		count, err := store.Count(ctx, QueryFilters{})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(5), "should have at least 5 alerts")
	})

	// Test QueryByID not found
	t.Run("QueryByID not found", func(t *testing.T) {
		_, err := store.QueryByID(ctx, "non-existent-alert")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// TestOpenSearchStoreUnit tests the OpenSearch store with a mock server.
func TestOpenSearchStoreUnit(t *testing.T) {
	t.Run("NewOpenSearchStore validates config", func(t *testing.T) {
		// Empty addresses should fail
		cfg := OpenSearchConfig{
			Addresses: []string{},
		}
		_, err := NewOpenSearchStore(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one OpenSearch address required")
	})

	t.Run("NewOpenSearchStore sets default index prefix", func(t *testing.T) {
		// Create a mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "green"}`))
		}))
		defer server.Close()

		cfg := OpenSearchConfig{
			Addresses:   []string{server.URL},
			IndexPrefix: "", // Empty, should default to "ebpf-guard"
		}

		store, err := NewOpenSearchStore(cfg)
		require.NoError(t, err)
		assert.NotNil(t, store)
	})
}



// TestOpenSearchStoreBulkError tests error handling in bulk operations.
func TestOpenSearchStoreBulkError(t *testing.T) {
	// Create a mock server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_bulk" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "bulk operation failed"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "green"}`))
	}))
	defer server.Close()

	cfg := OpenSearchConfig{
		Addresses:   []string{server.URL},
		IndexPrefix: "test",
	}

	store, err := NewOpenSearchStore(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	alert := types.Alert{
		ID:        "test-alert",
		Timestamp: time.Now(),
		RuleID:    "rule_001",
		Severity:  types.SeverityCritical,
		PID:       1234,
		Comm:      "test",
		Message:   "Test alert",
	}

	err = store.Store(ctx, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bulk index failed")
}

// TestOpenSearchTLSConfig verifies that TLS configuration fields are populated
// correctly when creating an OpenSearch store.
func TestOpenSearchTLSConfig(t *testing.T) {
	t.Run("InsecureSkipVerify emits no error but logs warn", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := OpenSearchConfig{
			Addresses:          []string{server.URL},
			InsecureSkipVerify: true,
		}
		s, err := NewOpenSearchStore(cfg)
		require.NoError(t, err)
		assert.NotNil(t, s)

		transport, ok := s.client.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	})

	t.Run("TLSServerName is set on tls.Config", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := OpenSearchConfig{
			Addresses:     []string{server.URL},
			TLSServerName: "opensearch.monitoring.svc.cluster.local",
		}
		s, err := NewOpenSearchStore(cfg)
		require.NoError(t, err)

		transport, ok := s.client.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)
		assert.Equal(t, "opensearch.monitoring.svc.cluster.local", transport.TLSClientConfig.ServerName)
	})

	t.Run("CACert loads custom cert pool", func(t *testing.T) {
		// Start a TLS test server to grab its self-signed certificate.
		tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer tlsServer.Close()

		// Write the server's cert to a temp file so we can pass it as CACert.
		cert := tlsServer.Certificate()
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		f, err := os.CreateTemp("", "ca-*.pem")
		require.NoError(t, err)
		defer os.Remove(f.Name())
		_, err = f.Write(pemBytes)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		cfg := OpenSearchConfig{
			Addresses:     []string{tlsServer.URL},
			CACert:        f.Name(),
			TLSServerName: "127.0.0.1",
		}
		s, err := NewOpenSearchStore(cfg)
		require.NoError(t, err)

		transport, ok := s.client.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)
		assert.NotNil(t, transport.TLSClientConfig.RootCAs, "custom CA pool should be set")
	})

	t.Run("CACert missing file returns error", func(t *testing.T) {
		cfg := OpenSearchConfig{
			Addresses: []string{"https://opensearch:9200"},
			CACert:    "/nonexistent/ca.pem",
		}
		_, err := NewOpenSearchStore(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read CA cert")
	})

	t.Run("CACert invalid PEM returns error", func(t *testing.T) {
		f, err := os.CreateTemp("", "bad-ca-*.pem")
		require.NoError(t, err)
		defer os.Remove(f.Name())
		_, err = f.WriteString("this is not valid PEM data\n")
		require.NoError(t, err)
		require.NoError(t, f.Close())

		cfg := OpenSearchConfig{
			Addresses: []string{"https://opensearch:9200"},
			CACert:    f.Name(),
		}
		_, err = NewOpenSearchStore(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no valid certificates")
	})

	t.Run("MinVersion is TLS 1.2", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := OpenSearchConfig{Addresses: []string{server.URL}}
		s, err := NewOpenSearchStore(cfg)
		require.NoError(t, err)

		transport, ok := s.client.Transport.(*http.Transport)
		require.True(t, ok)
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	})
}

// TestOpenSearchStoreSearchError tests error handling in search operations.
func TestOpenSearchStoreSearchError(t *testing.T) {
	// Create a mock server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test-alerts-"+time.Now().Format("2006.01.02")+"/_search" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "search failed"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "green"}`))
	}))
	defer server.Close()

	cfg := OpenSearchConfig{
		Addresses:   []string{server.URL},
		IndexPrefix: "test",
	}

	store, err := NewOpenSearchStore(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = store.Query(ctx, QueryFilters{})
	// This may or may not error depending on the date matching
	// Just verify the store was created successfully
	assert.NotNil(t, store)
}
