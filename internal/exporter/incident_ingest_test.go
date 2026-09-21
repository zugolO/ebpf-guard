package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Волна 6.3.L.1, item 2 (№423): рантайм-ручка инцидентного слоя. Проверяется
// ровно то, на чём держится A/B: не подключённый тумблер отличим от
// выключенного слоя (503 против enabled=false), а POST сообщает, ДВИНУЛСЯ ли
// он — окно A/B не вправе записать переход, которого не было.
func TestHandleIncidentIngest(t *testing.T) {
	t.Run("not wired answers 503", func(t *testing.T) {
		srv := newTestServer()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tuning/incident-ingest", nil)
		w := httptest.NewRecorder()
		srv.handleIncidentIngest(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	newWired := func() (*Server, *atomic.Bool) {
		state := &atomic.Bool{}
		state.Store(true)
		srv := newTestServer()
		srv.SetRuntimeSwitch("incident-ingest", state.Load, state.Store)
		return srv, state
	}

	t.Run("GET reports state without changing it", func(t *testing.T) {
		srv, state := newWired()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tuning/incident-ingest", nil)
		w := httptest.NewRecorder()
		srv.handleIncidentIngest(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp IncidentIngestStateResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.Enabled)
		assert.False(t, resp.Changed)
		assert.True(t, state.Load())
	})

	t.Run("POST flips the state and reports the transition", func(t *testing.T) {
		srv, state := newWired()
		body, _ := json.Marshal(map[string]bool{"enabled": false})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/incident-ingest", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleIncidentIngest(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp IncidentIngestStateResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.Enabled)
		assert.True(t, resp.Changed)
		assert.False(t, state.Load())

		// Повторная подача того же значения — не переход.
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/incident-ingest", bytes.NewReader(body))
		w2 := httptest.NewRecorder()
		srv.handleIncidentIngest(w2, req2)
		require.Equal(t, http.StatusOK, w2.Code)
		var resp2 IncidentIngestStateResponse
		require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp2))
		assert.False(t, resp2.Changed)
	})

	t.Run("POST without enabled is a 400", func(t *testing.T) {
		srv, _ := newWired()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/incident-ingest", bytes.NewReader([]byte(`{}`)))
		w := httptest.NewRecorder()
		srv.handleIncidentIngest(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	// Второй тумблер того же семейства (item 4, №425) обслуживается тем же
	// кодом и обязан быть ОТДЕЛЬНЫМ: включение агрегации не вправе
	// выключить инцидентный слой и наоборот.
	t.Run("alert-aggregation is a separate switch", func(t *testing.T) {
		srv, incident := newWired()
		agg := &atomic.Bool{}
		srv.SetRuntimeSwitch("alert-aggregation", agg.Load, agg.Store)

		body, _ := json.Marshal(map[string]bool{"enabled": true})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/alert-aggregation", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleAlertAggregation(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.True(t, agg.Load())
		assert.True(t, incident.Load(), "инцидентный тумблер не тронут")
	})

	t.Run("viewer cannot flip the switch", func(t *testing.T) {
		srv, state := newWired()
		body, _ := json.Marshal(map[string]bool{"enabled": false})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/incident-ingest", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), tokenScopeKey{}, TokenScope{Role: RoleViewer}))
		w := httptest.NewRecorder()
		srv.handleIncidentIngest(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.True(t, state.Load())
	})
}
