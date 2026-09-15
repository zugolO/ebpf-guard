package exporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Волна 6.3, item 4 (№328, открытый вопрос 4): per-collector `stale` в
// /health. До этой правки GET /health/ready нёс []CollectorStatus, но без
// поля Stale вовсе, а GET /health не нёс per-collector срез ни в каком
// виде — коллектор мог быть attached+healthy и производить события на
// приборно неправдоподобном темпе, и /health молчал об этом целиком.

func TestSetCollectorStale_PreservesHealthyAndError(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetCollectorStatus(CollectorStatus{Name: "dns", Healthy: true})

	s.SetCollectorStale("dns", true)

	status := s.getHealthStatus()
	require.Len(t, status.Collectors, 1)
	assert.Equal(t, "dns", status.Collectors[0].Name)
	assert.True(t, status.Collectors[0].Healthy, "SetCollectorStale must not clear Healthy")
	assert.True(t, status.Collectors[0].Stale)

	s.SetCollectorStale("dns", false)
	status = s.getHealthStatus()
	require.Len(t, status.Collectors, 1)
	assert.True(t, status.Collectors[0].Healthy, "clearing Stale must not touch Healthy either")
	assert.False(t, status.Collectors[0].Stale)
}

func TestSetCollectorStale_PreservesErrorMessage(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetCollectorStatus(CollectorStatus{Name: "dns", Healthy: false, Error: "attach failed"})

	s.SetCollectorStale("dns", true)

	status := s.getHealthStatus()
	require.Len(t, status.Collectors, 1)
	assert.Equal(t, "attach failed", status.Collectors[0].Error, "SetCollectorStale must not clear a prior Error")
	assert.False(t, status.Collectors[0].Healthy)
	assert.True(t, status.Collectors[0].Stale)
}

// A collector that never reports staleness (everything but DNS today) must
// not show up as Stale by default — the zero value, and the field stays
// omitted from JSON via omitempty.
func TestGetHealthStatus_CollectorsWithoutStaleReportDefaultFalse(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetCollectorStatus(CollectorStatus{Name: "syscall", Healthy: true})

	status := s.getHealthStatus()
	require.Len(t, status.Collectors, 1)
	assert.False(t, status.Collectors[0].Stale)
}

func TestGetHealthStatus_CollectorsSortedByName(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetCollectorStatus(CollectorStatus{Name: "syscall", Healthy: true})
	s.SetCollectorStatus(CollectorStatus{Name: "dns", Healthy: true})
	s.SetCollectorStatus(CollectorStatus{Name: "network", Healthy: true})

	status := s.getHealthStatus()
	require.Len(t, status.Collectors, 3)
	assert.Equal(t, []string{"dns", "network", "syscall"},
		[]string{status.Collectors[0].Name, status.Collectors[1].Name, status.Collectors[2].Name})
}

func TestGetHealthStatus_NoCollectorsRegisteredYieldsEmptySlice(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	status := s.getHealthStatus()
	assert.Empty(t, status.Collectors)
}
