package exporter

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	server := NewServer(":0", "/metrics", "/health")
	
	assert.NotNil(t, server)
	assert.Equal(t, ":0", server.bindAddress)
	assert.Equal(t, "/metrics", server.metricsPath)
	assert.Equal(t, "/health", server.healthPath)
	assert.True(t, server.healthy)
	assert.False(t, server.ready)
}

func TestNewServer_DefaultPaths(t *testing.T) {
	server := NewServer(":9090", "", "")
	
	assert.Equal(t, "/metrics", server.metricsPath)
	assert.Equal(t, "/health", server.healthPath)
}

func TestServer_HealthEndpoints(t *testing.T) {
	// Listen on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	
	addr := listener.Addr().String()
	server := NewServer(addr, "/metrics", "/health")
	
	// Start server in background
	go func() {
		server.server.Serve(listener)
	}()
	
	// Wait for server to start
	time.Sleep(50 * time.Millisecond)
	
	baseURL := "http://" + addr
	
	// Test /health/live (liveness)
	server.SetHealthy(true)
	resp, err := http.Get(baseURL + "/health/live")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "alive\n", string(body))
	resp.Body.Close()
	
	// Test /health/ready (readiness) - not ready yet
	resp, err = http.Get(baseURL + "/health/ready")
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
	
	// Mark as ready
	server.SetReady(true)
	resp, err = http.Get(baseURL + "/health/ready")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ = io.ReadAll(resp.Body)
	// Response is now JSON with collector status
	assert.Contains(t, string(body), "ready")
	resp.Body.Close()
	
	// Test /health (comprehensive)
	resp, err = http.Get(baseURL + "/health")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var status HealthStatus
	err = json.NewDecoder(resp.Body).Decode(&status)
	require.NoError(t, err)
	resp.Body.Close()
	
	assert.True(t, status.Healthy)
	assert.True(t, status.Ready)
	assert.Greater(t, status.Uptime, time.Duration(0))
}

func TestServer_Health_Unhealthy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	
	addr := listener.Addr().String()
	server := NewServer(addr, "/metrics", "/health")
	
	go func() {
		server.server.Serve(listener)
	}()
	
	time.Sleep(50 * time.Millisecond)
	
	baseURL := "http://" + addr
	
	// Mark as unhealthy
	server.SetHealthy(false)
	server.SetReady(true)
	
	resp, err := http.Get(baseURL + "/health")
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
	
	// Liveness should also fail
	resp, err = http.Get(baseURL + "/health/live")
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
}

func TestServer_MetricsEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	
	addr := listener.Addr().String()
	server := NewServer(addr, "/metrics", "/health")
	
	go func() {
		server.server.Serve(listener)
	}()
	
	time.Sleep(50 * time.Millisecond)
	
	baseURL := "http://" + addr
	
	resp, err := http.Get(baseURL + "/metrics")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
	resp.Body.Close()
}

func TestServer_getHealthStatus(t *testing.T) {
	server := NewServer(":9090", "/metrics", "/health")
	
	// Wait a bit to ensure uptime > 0
	time.Sleep(10 * time.Millisecond)
	
	server.SetHealthy(true)
	server.SetReady(true)
	
	status := server.getHealthStatus()
	
	assert.True(t, status.Healthy)
	assert.True(t, status.Ready)
	assert.GreaterOrEqual(t, status.Uptime, 10*time.Millisecond)
	assert.False(t, status.Timestamp.IsZero())
}
