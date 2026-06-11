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

// responseRecorder is a minimal http.ResponseWriter for unit tests.
type responseRecorder struct {
	code int
	body []byte
	hdr  http.Header
}

func newRecorder() *responseRecorder {
	return &responseRecorder{code: http.StatusOK, hdr: make(http.Header)}
}
func (r *responseRecorder) Header() http.Header         { return r.hdr }
func (r *responseRecorder) WriteHeader(code int)        { r.code = code }
func (r *responseRecorder) Write(b []byte) (int, error) { r.body = append(r.body, b...); return len(b), nil }

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

func TestServer_RequiredCollectors_ReadyEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().String()
	server := NewServer(addr, "/metrics", "/health")
	server.SetRequired([]string{"syscall", "network"})
	server.SetReady(true)

	go func() { server.server.Serve(listener) }()
	time.Sleep(50 * time.Millisecond)

	baseURL := "http://" + addr

	// All collectors up → 200
	server.SetCollectorStatus(CollectorStatus{Name: "syscall", Healthy: true})
	server.SetCollectorStatus(CollectorStatus{Name: "network", Healthy: true})
	server.SetCollectorStatus(CollectorStatus{Name: "tls", Healthy: false}) // optional collector down
	resp, err := http.Get(baseURL + "/health/ready")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "optional collector failure must not block readiness")
	resp.Body.Close()

	// Required collector down → 503
	server.SetCollectorStatus(CollectorStatus{Name: "syscall", Healthy: false, Error: "bpf attach failed"})
	resp, err = http.Get(baseURL + "/health/ready")
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	failed, ok := body["failed_required_collectors"]
	require.True(t, ok, "response must include failed_required_collectors")
	assert.Contains(t, failed, "syscall")
}

func TestServer_RequiredCollectors_NoRequired_AllCollectorsRequired(t *testing.T) {
	// When no required list is set, any unhealthy collector blocks readiness.
	server := NewServer(":0", "/metrics", "/health")
	server.SetReady(true)
	server.SetCollectorStatus(CollectorStatus{Name: "dns", Healthy: false, Error: "timeout"})

	req, _ := http.NewRequest(http.MethodGet, "/health/ready", nil)
	rr := newRecorder()
	server.handleReady(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.code)
}
