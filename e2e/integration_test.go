// Package e2e provides end-to-end integration tests for ebpf-guard.
// These tests require Docker and may require privileged mode for eBPF operations.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// IntegrationTestSuite provides end-to-end testing infrastructure.
type IntegrationTestSuite struct {
	suite.Suite
	ctx       context.Context
	cancel    context.CancelFunc
	network   testcontainers.Network
	container testcontainers.Container
}

// SetupSuite initializes the test environment.
func (s *IntegrationTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("skipping integration tests in -short mode")
	}

	s.ctx, s.cancel = context.WithTimeout(context.Background(), 10*time.Minute)

	// Create a Docker network
	network, err := testcontainers.GenericNetwork(s.ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           "ebpf-guard-test",
			CheckDuplicate: true,
		},
	})
	require.NoError(s.T(), err)
	s.network = network
}

// TearDownSuite cleans up the test environment.
func (s *IntegrationTestSuite) TearDownSuite() {
	if s.container != nil {
		s.container.Terminate(s.ctx)
	}
	if s.network != nil {
		s.network.Remove(s.ctx)
	}
	s.cancel()
}

// TestHealthEndpoint verifies the health endpoint responds correctly.
func (s *IntegrationTestSuite) TestHealthEndpoint() {
	// Build the test image
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "..",
			Dockerfile:    "Dockerfile",
			PrintBuildLog: true,
		},
		ExposedPorts: []string{"9090/tcp"},
		WaitingFor:   wait.ForHTTP("/health").WithPort("9090").WithStartupTimeout(30 * time.Second),
		Networks:     []string{"ebpf-guard-test"},
		Privileged:   true, // Required for eBPF
	}

	container, err := testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(s.T(), err)
	s.container = container

	// Get the container IP
	ip, err := container.Host(s.ctx)
	require.NoError(s.T(), err)

	port, err := container.MappedPort(s.ctx, "9090")
	require.NoError(s.T(), err)

	// Test health endpoint
	url := fmt.Sprintf("http://%s:%s/health", ip, port.Port())
	resp, err := http.Get(url)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// TestMetricsEndpoint verifies Prometheus metrics are exported.
func (s *IntegrationTestSuite) TestMetricsEndpoint() {
	if s.container == nil {
		s.T().Skip("Container not running")
	}

	ip, err := s.container.Host(s.ctx)
	require.NoError(s.T(), err)

	port, err := s.container.MappedPort(s.ctx, "9090")
	require.NoError(s.T(), err)

	url := fmt.Sprintf("http://%s:%s/metrics", ip, port.Port())
	resp, err := http.Get(url)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
	assert.Contains(s.T(), resp.Header.Get("Content-Type"), "text/plain")
}

// TestReadyEndpoint verifies the readiness probe.
func (s *IntegrationTestSuite) TestReadyEndpoint() {
	if s.container == nil {
		s.T().Skip("Container not running")
	}

	ip, err := s.container.Host(s.ctx)
	require.NoError(s.T(), err)

	port, err := s.container.MappedPort(s.ctx, "9090")
	require.NoError(s.T(), err)

	url := fmt.Sprintf("http://%s:%s/health/ready", ip, port.Port())
	resp, err := http.Get(url)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// TestLiveEndpoint verifies the liveness probe.
func (s *IntegrationTestSuite) TestLiveEndpoint() {
	if s.container == nil {
		s.T().Skip("Container not running")
	}

	ip, err := s.container.Host(s.ctx)
	require.NoError(s.T(), err)

	port, err := s.container.MappedPort(s.ctx, "9090")
	require.NoError(s.T(), err)

	url := fmt.Sprintf("http://%s:%s/health/live", ip, port.Port())
	resp, err := http.Get(url)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// RunIntegrationTests runs the integration test suite.
func RunIntegrationTests(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}

// TestIntegration is the entry point for e2e tests.
func TestIntegration(t *testing.T) {
	RunIntegrationTests(t)
}
