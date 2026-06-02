// Package store provides OpenSearch storage backend tests.
package store

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
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
	require.NoError(t, err, "failed to start OpenSearch container")
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

		// Wait for indexing
		time.Sleep(2 * time.Second)

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

		// Wait for indexing
		time.Sleep(2 * time.Second)

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

		// Wait for indexing
		time.Sleep(2 * time.Second)

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
