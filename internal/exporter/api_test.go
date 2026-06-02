package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAlertStore is a mock implementation of store.AlertStore for testing
type mockAlertStore struct {
	alerts []types.Alert
	healthy bool
}

func (m *mockAlertStore) Store(ctx context.Context, alert types.Alert) error {
	m.alerts = append(m.alerts, alert)
	return nil
}

func (m *mockAlertStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	m.alerts = append(m.alerts, alerts...)
	return nil
}

func (m *mockAlertStore) Query(ctx context.Context, filters store.QueryFilters) ([]types.Alert, error) {
	var result []types.Alert
	for _, alert := range m.alerts {
		// Apply filters
		if len(filters.Severity) > 0 {
			match := false
			for _, s := range filters.Severity {
				if alert.Severity == s {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if filters.PodName != "" && alert.Enrichment.PodName != filters.PodName {
			continue
		}
		if filters.Namespace != "" && alert.Enrichment.Namespace != filters.Namespace {
			continue
		}
		result = append(result, alert)
	}
	
	// Apply limit
	if filters.Limit > 0 && len(result) > filters.Limit {
		result = result[:filters.Limit]
	}
	
	return result, nil
}

func (m *mockAlertStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) {
	for _, alert := range m.alerts {
		if alert.ID == alertID {
			return &alert, nil
		}
	}
	return nil, fmt.Errorf("alert not found")
}

func (m *mockAlertStore) Count(ctx context.Context, filters store.QueryFilters) (int64, error) {
	alerts, err := m.Query(ctx, filters)
	return int64(len(alerts)), err
}

func (m *mockAlertStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	var newAlerts []types.Alert
	var deleted int64
	for _, alert := range m.alerts {
		if alert.Timestamp.Before(cutoff) {
			deleted++
		} else {
			newAlerts = append(newAlerts, alert)
		}
	}
	m.alerts = newAlerts
	return deleted, nil
}

func (m *mockAlertStore) Close() error {
	return nil
}

func (m *mockAlertStore) Healthy(ctx context.Context) bool {
	return m.healthy
}

func TestHandleAlerts(t *testing.T) {
	mockStore := &mockAlertStore{
		alerts: []types.Alert{
			{
				ID:        "alert-1",
				Timestamp: time.Now(),
				RuleID:    "rule_001",
				RuleName:  "Test Rule",
				Severity:  types.SeverityCritical,
				PID:       1234,
				Comm:      "test",
				Message:   "Test alert",
			},
			{
				ID:        "alert-2",
				Timestamp: time.Now(),
				RuleID:    "rule_002",
				RuleName:  "Warning Rule",
				Severity:  types.SeverityWarning,
				PID:       5678,
				Comm:      "test2",
				Message:   "Warning alert",
			},
		},
		healthy: true,
	}

	srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)
	srv.SetAlertStore(mockStore)

	t.Run("GET /api/v1/alerts returns all alerts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
		w := httptest.NewRecorder()

		srv.handleAlerts(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var alerts []types.Alert
		err := json.Unmarshal(w.Body.Bytes(), &alerts)
		require.NoError(t, err)
		assert.Len(t, alerts, 2)
	})

	t.Run("GET /api/v1/alerts with severity filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts?severity=critical", nil)
		w := httptest.NewRecorder()

		srv.handleAlerts(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var alerts []types.Alert
		err := json.Unmarshal(w.Body.Bytes(), &alerts)
		require.NoError(t, err)
		assert.Len(t, alerts, 1)
		assert.Equal(t, types.SeverityCritical, alerts[0].Severity)
	})

	t.Run("GET /api/v1/alerts with limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts?limit=1", nil)
		w := httptest.NewRecorder()

		srv.handleAlerts(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var alerts []types.Alert
		err := json.Unmarshal(w.Body.Bytes(), &alerts)
		require.NoError(t, err)
		assert.Len(t, alerts, 1)
	})

	t.Run("POST /api/v1/alerts returns method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", nil)
		w := httptest.NewRecorder()

		srv.handleAlerts(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("GET /api/v1/alerts without store returns service unavailable", func(t *testing.T) {
		srvWithoutStore := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)
		
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
		w := httptest.NewRecorder()

		srvWithoutStore.handleAlerts(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestHandleAlertByID(t *testing.T) {
	mockStore := &mockAlertStore{
		alerts: []types.Alert{
			{
				ID:        "alert-1",
				Timestamp: time.Now(),
				RuleID:    "rule_001",
				RuleName:  "Test Rule",
				Severity:  types.SeverityCritical,
				PID:       1234,
				Comm:      "test",
				Message:   "Test alert",
			},
		},
		healthy: true,
	}

	srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)
	srv.SetAlertStore(mockStore)

	t.Run("GET /api/v1/alerts/{id} returns alert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/alert-1", nil)
		w := httptest.NewRecorder()

		srv.handleAlertByID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var alert types.Alert
		err := json.Unmarshal(w.Body.Bytes(), &alert)
		require.NoError(t, err)
		assert.Equal(t, "alert-1", alert.ID)
	})

	t.Run("GET /api/v1/alerts/{id} returns 404 for unknown alert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/unknown", nil)
		w := httptest.NewRecorder()

		srv.handleAlertByID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestHandleStatus(t *testing.T) {
	mockStore := &mockAlertStore{healthy: true}

	srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)
	srv.SetAlertStore(mockStore)
	srv.SetHealthy(true)
	srv.SetReady(true)

	t.Run("GET /api/v1/status returns status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		w := httptest.NewRecorder()

		srv.handleStatus(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var status StatusAPIResponse
		err := json.Unmarshal(w.Body.Bytes(), &status)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.True(t, status.Ready)
		assert.NotEmpty(t, status.Uptime)
		assert.Equal(t, "healthy", status.Store)
	})

	t.Run("POST /api/v1/status returns method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/status", nil)
		w := httptest.NewRecorder()

		srv.handleStatus(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestHandleRules(t *testing.T) {
	rules := []correlator.Rule{
		{
			ID:          "rule_001",
			Name:        "Test Rule",
			Description: "A test rule",
			EventType:   types.EventSyscall,
			Condition: correlator.RuleCondition{
				Field:  "nr",
				Op:     correlator.OpEquals,
				Values: []string{"1"},
			},
			Severity: types.SeverityCritical,
			Action:   correlator.ActionAlert,
			Tags:     []string{"test", "syscall"},
		},
		{
			ID:          "rule_002",
			Name:        "Network Rule",
			Description: "A network rule",
			EventType:   types.EventTCPConnect,
			Condition: correlator.RuleCondition{
				Field:  "dport",
				Op:     correlator.OpEquals,
				Values: []string{"8080"},
			},
			Severity: types.SeverityWarning,
			Action:   correlator.ActionAlert,
			Tags:     []string{"network"},
		},
	}

	srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)
	srv.SetRulesProvider(func() []correlator.Rule {
		return rules
	})

	t.Run("GET /api/v1/rules returns all rules", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		w := httptest.NewRecorder()

		srv.handleRules(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []RuleAPIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response, 2)
		assert.Equal(t, "rule_001", response[0].ID)
		assert.Equal(t, "syscall", response[0].EventType)
		assert.Equal(t, []string{"test", "syscall"}, response[0].Tags)
	})

	t.Run("POST /api/v1/rules returns method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
		w := httptest.NewRecorder()

		srv.handleRules(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestHandleRulesReload(t *testing.T) {
	t.Run("POST /api/v1/rules/reload triggers reload", func(t *testing.T) {
		reloadCalled := false
		srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)
		srv.SetRulesReloadHandler(func() error {
			reloadCalled = true
			return nil
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/reload", nil)
		w := httptest.NewRecorder()

		srv.handleRulesReload(w, req)

		assert.Equal(t, http.StatusAccepted, w.Code)
		assert.True(t, reloadCalled)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "accepted", response["status"])
	})

	t.Run("POST /api/v1/rules/reload without handler returns 404", func(t *testing.T) {
		srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/reload", nil)
		w := httptest.NewRecorder()

		srv.handleRulesReload(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("POST /api/v1/rules/reload with error returns 500", func(t *testing.T) {
		srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)
		srv.SetRulesReloadHandler(func() error {
			return fmt.Errorf("reload failed")
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/reload", nil)
		w := httptest.NewRecorder()

		srv.handleRulesReload(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("GET /api/v1/rules/reload returns method not allowed", func(t *testing.T) {
		srv := NewServerWithAuth("localhost:9090", "/metrics", "/health", false, false, "", false)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/reload", nil)
		w := httptest.NewRecorder()

		srv.handleRulesReload(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestParseQueryFilters(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected store.QueryFilters
	}{
		{
			name:     "empty query",
			query:    "",
			expected: store.QueryFilters{},
		},
		{
			name:  "with severity",
			query: "severity=critical",
			expected: store.QueryFilters{
				Severity: []types.Severity{types.SeverityCritical},
			},
		},
		{
			name:  "with multiple severities",
			query: "severity=critical,warning",
			expected: store.QueryFilters{
				Severity: []types.Severity{types.SeverityCritical, types.SeverityWarning},
			},
		},
		{
			name:  "with limit",
			query: "limit=10",
			expected: store.QueryFilters{
				Limit: 10,
			},
		},
		{
			name:  "with pid",
			query: "pid=1234",
			expected: store.QueryFilters{
				PIDs: []uint32{1234},
			},
		},
		{
			name:  "with pod and namespace",
			query: "pod=mypod&namespace=default",
			expected: store.QueryFilters{
				PodName:   "mypod",
				Namespace: "default",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts?"+tt.query, nil)
			filters := parseQueryFilters(req)

			assert.Equal(t, tt.expected.Severity, filters.Severity)
			assert.Equal(t, tt.expected.Limit, filters.Limit)
			assert.Equal(t, tt.expected.PIDs, filters.PIDs)
			assert.Equal(t, tt.expected.PodName, filters.PodName)
			assert.Equal(t, tt.expected.Namespace, filters.Namespace)
		})
	}
}

func TestFormatCEF(t *testing.T) {
	alert := types.Alert{
		ID:        "alert-1",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityCritical,
		PID:       1234,
		Comm:      "test|app",
		Message:   "Test=Alert",
		Enrichment: types.EnrichmentInfo{
			PodName:   "mypod",
			Namespace: "default",
		},
	}

	cef := formatCEF(alert)

	// Verify CEF format components
	assert.Contains(t, cef, "CEF:0|ebpf-guard|ebpf-guard|1.0|")
	assert.Contains(t, cef, "rule_001")
	assert.Contains(t, cef, "10") // Critical severity
	assert.Contains(t, cef, "rt=1705314600000")
	assert.Contains(t, cef, "deviceProcessName=test\\|app") // Escaped pipe
	assert.Contains(t, cef, "dpid=1234")
	assert.Contains(t, cef, "dhost=mypod")
	assert.Contains(t, cef, "cs2=default")
}
