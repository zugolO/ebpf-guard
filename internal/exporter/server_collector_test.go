package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_CollectorStatus(t *testing.T) {
	server := NewServer("localhost:0", "/metrics", "/health")

	// Initially no collectors registered
	statuses := server.GetCollectorStatuses()
	assert.Empty(t, statuses)
	assert.True(t, server.AllCollectorsHealthy())

	// Set a healthy collector
	server.SetCollectorStatus(CollectorStatus{
		Name:    "syscall",
		Healthy: true,
	})

	statuses = server.GetCollectorStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "syscall", statuses[0].Name)
	assert.True(t, statuses[0].Healthy)
	assert.True(t, server.AllCollectorsHealthy())

	// Set an unhealthy collector
	server.SetCollectorStatus(CollectorStatus{
		Name:    "network",
		Healthy: false,
		Error:   "stub mode: bpf2go not generated",
	})

	statuses = server.GetCollectorStatuses()
	require.Len(t, statuses, 2)
	assert.False(t, server.AllCollectorsHealthy())
}

func TestServer_HandleReady_AllHealthy(t *testing.T) {
	server := NewServer("localhost:0", "/metrics", "/health")
	server.SetReady(true)
	server.SetCollectorStatus(CollectorStatus{
		Name:    "syscall",
		Healthy: true,
	})
	server.SetCollectorStatus(CollectorStatus{
		Name:    "network",
		Healthy: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "ready", response["status"])
	collectors, ok := response["collectors"].([]interface{})
	require.True(t, ok)
	assert.Len(t, collectors, 2)
}

func TestServer_HandleReady_WithFailedCollectors(t *testing.T) {
	server := NewServer("localhost:0", "/metrics", "/health")
	server.SetReady(true)
	server.SetCollectorStatus(CollectorStatus{
		Name:    "syscall",
		Healthy: true,
	})
	server.SetCollectorStatus(CollectorStatus{
		Name:    "network",
		Healthy: false,
		Error:   "stub mode: bpf2go not generated",
	})

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "not ready", response["status"])
	
	failedCollectors, ok := response["failed_collectors"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, failedCollectors, "network")
	assert.NotContains(t, failedCollectors, "syscall")
}

func TestServer_HandleReady_NotReady(t *testing.T) {
	server := NewServer("localhost:0", "/metrics", "/health")
	server.SetReady(false)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "not ready", response["status"])
	assert.Equal(t, "server not ready", response["reason"])
}

func TestCollectorUpMetric(t *testing.T) {
	// Reset metric
	CollectorUp.Reset()

	// Set collectors up/down
	SetCollectorUp("syscall", true)
	SetCollectorUp("network", false)
	SetCollectorUp("fileaccess", true)

	// Verify metric values
	assert.Equal(t, float64(1), testutil.ToFloat64(CollectorUp.WithLabelValues("syscall")))
	assert.Equal(t, float64(0), testutil.ToFloat64(CollectorUp.WithLabelValues("network")))
	assert.Equal(t, float64(1), testutil.ToFloat64(CollectorUp.WithLabelValues("fileaccess")))
}
