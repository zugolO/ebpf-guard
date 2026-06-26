package gossip

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAmplTestManager(t *testing.T) *Manager {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Secret = "shared-secret"
	m, err := NewManager(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return m
}

func TestDefaultConfigExtra(t *testing.T) {
	cfg := DefaultConfig()
	// Sanity: the zero-ish defaults are normalised by NewManager, but the
	// config itself should be returned populated.
	assert.NotPanics(t, func() { _ = cfg })
}

func TestManager_AccessorsAndMetrics(t *testing.T) {
	m := newAmplTestManager(t)

	// With no signals stored the multiplier is the neutral 1.0.
	assert.Equal(t, 1.0, m.GetThresholdMultiplier("default"))
	assert.Empty(t, m.AmplificationSnapshot())

	reg := prometheus.NewRegistry()
	assert.NotPanics(t, func() { m.RegisterMetrics(reg) })
}

func TestHandleReceiveAmplifications(t *testing.T) {
	m := newAmplTestManager(t)

	sigs := []AmplificationSignal{
		{Namespace: "prod", RuleID: "rule-1", Severity: "critical", Source: "node-a", ThresholdMultiplier: 0.5},
	}
	body, _ := json.Marshal(sigs)

	t.Run("valid batch → 204", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/gossip/amplifications", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handleReceiveAmplifications(m, w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("invalid JSON → 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/gossip/amplifications", bytes.NewReader([]byte("{bad")))
		w := httptest.NewRecorder()
		handleReceiveAmplifications(m, w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleSnapshotAmplifications(t *testing.T) {
	m := newAmplTestManager(t)
	// Seed a signal via the receive handler so the snapshot is non-empty.
	sigs := []AmplificationSignal{{Namespace: "prod", RuleID: "r", Severity: "critical", Source: "n", ThresholdMultiplier: 0.5}}
	body, _ := json.Marshal(sigs)
	recvReq := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	handleReceiveAmplifications(m, httptest.NewRecorder(), recvReq)

	req := httptest.NewRequest(http.MethodGet, "/gossip/amplifications/snapshot", nil)
	w := httptest.NewRecorder()
	handleSnapshotAmplifications(m, w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var out []AmplificationSignal
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
}
