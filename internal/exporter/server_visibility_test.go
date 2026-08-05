package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHealth_DegradedWhenVisibilityReduced covers the P0-25 acceptance
// criterion "at any nonzero loss, /health shows degradation". Run #4 lost 52%
// of network events while /health reported plain success, which is what made
// every downstream measurement untrustworthy.
func TestHealth_DegradedWhenVisibilityReduced(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetHealthy(true)

	// Baseline: no drops → healthy, and the flag is absent.
	status := s.getHealthStatus()
	assert.Equal(t, HealthStatusHealthy, status.Status)
	assert.False(t, status.VisibilityReduced)

	s.SetVisibilityReduced(true)

	status = s.getHealthStatus()
	assert.Equal(t, HealthStatusDegraded, status.Status)
	assert.True(t, status.VisibilityReduced)
	// Degraded is not unhealthy: the agent still works, so it must not be
	// restarted by an orchestrator watching the health probe.
	assert.True(t, status.Healthy, "degraded must stay healthy=true so probes do not restart a working agent")

	// The getter used by the agent-health provider must agree.
	assert.True(t, s.VisibilityReduced())

	// And it must clear again.
	s.SetVisibilityReduced(false)
	assert.Equal(t, HealthStatusHealthy, s.getHealthStatus().Status)
	assert.False(t, s.VisibilityReduced())
}

// TestHealth_UnhealthyOutranksDegraded pins the precedence so a genuinely
// broken agent is never softened to "degraded".
func TestHealth_UnhealthyOutranksDegraded(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetHealthy(false)
	s.SetVisibilityReduced(true)

	assert.Equal(t, HealthStatusUnhealthy, s.getHealthStatus().Status)
}

// TestHealth_StatusFieldIsServed makes sure the field actually reaches the
// wire — a gate script parses this JSON, not the Go struct.
func TestHealth_StatusFieldIsServed(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetHealthy(true)
	s.SetVisibilityReduced(true)

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	require.Equal(t, http.StatusOK, rec.Code, "degraded still serves 200")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, HealthStatusDegraded, body["status"])
	assert.Equal(t, true, body["visibility_reduced"])
}

// TestHealth_BulkOnlyDropStillDegrades covers plan.md 1.5b: a bulk-queue-only
// drop (file events under load, no protected-queue loss) must still surface
// as degraded, and DegradedQueues must report "bulk" so an operator can tell
// it apart from a protected-queue (signal) loss.
func TestHealth_BulkOnlyDropStillDegrades(t *testing.T) {
	s := NewServer(":0", "/metrics", "/health")
	s.SetHealthy(true)

	// Simulate what main.go's degradation goroutine does on a bulk-only drop:
	// VisibilityReduced flips true, DegradedQueues names only "bulk".
	s.SetDegradedQueues([]string{"bulk"})
	s.SetVisibilityReduced(true)

	status := s.getHealthStatus()
	assert.Equal(t, HealthStatusDegraded, status.Status, "bulk-only drop must still degrade /health")
	assert.True(t, status.VisibilityReduced)
	assert.Equal(t, []string{"bulk"}, status.DegradedQueues)

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, []any{"bulk"}, body["degraded_queues"])
}
