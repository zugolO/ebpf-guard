package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentHealthProvider(t *testing.T) {
	srv := newTestServer()

	t.Run("omitted when no provider configured", func(t *testing.T) {
		_, ok := srv.getAgentHealth()
		assert.False(t, ok)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		w := httptest.NewRecorder()
		srv.handleStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp StatusAPIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Nil(t, resp.Health)
	})

	t.Run("included once configured", func(t *testing.T) {
		srv.SetAgentHealthProvider(func() AgentHealth {
			return AgentHealth{
				CPUPressureLevel:       1,
				CPUPressurePercent:     42.5,
				VisibilityReduced:      true,
				SamplingRates:          map[string]float64{"file": 0.1},
				DriftLearningWorkloads: 3,
				DriftStuckWorkloads:    1,
				DriftProfilesActive:    10,
				HardwareProfile:        "balanced",
			}
		})

		health, ok := srv.getAgentHealth()
		require.True(t, ok)
		assert.Equal(t, "balanced", health.HardwareProfile)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		w := httptest.NewRecorder()
		srv.handleStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp StatusAPIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.NotNil(t, resp.Health)
		assert.Equal(t, 1, resp.Health.CPUPressureLevel)
		assert.InDelta(t, 42.5, resp.Health.CPUPressurePercent, 0.001)
		assert.True(t, resp.Health.VisibilityReduced)
		assert.Equal(t, 0.1, resp.Health.SamplingRates["file"])
		assert.Equal(t, 3, resp.Health.DriftLearningWorkloads)
		assert.Equal(t, 1, resp.Health.DriftStuckWorkloads)
		assert.Equal(t, 10, resp.Health.DriftProfilesActive)
	})
}
