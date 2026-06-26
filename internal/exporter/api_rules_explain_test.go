package exporter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ruleWithGroup() correlator.Rule {
	return correlator.Rule{
		ID:        "rule-grp",
		Name:      "Grouped rule",
		EventType: types.EventSyscall,
		Severity:  types.SeverityCritical,
		Action:    "alert",
		ConditionGroup: &correlator.RuleConditionGroup{
			Operator: "and",
			Conditions: []correlator.RuleCondition{
				{Field: "comm", Op: "eq", Values: []string{"evil"}},
			},
			SubGroups: []correlator.RuleConditionGroup{
				{
					Operator:   "or",
					Conditions: []correlator.RuleCondition{{Field: "uid", Op: "eq", Values: []string{"0"}}},
				},
			},
		},
	}
}

func TestConvertRuleToAPI_WithGroup(t *testing.T) {
	resp := convertRuleToAPI(ruleWithGroup())
	assert.Equal(t, "rule-grp", resp.ID)
	require.NotNil(t, resp.ConditionGroup)
	assert.Equal(t, "and", resp.ConditionGroup.Operator)
	assert.NotEmpty(t, resp.ConditionGroup.Conditions)

	assert.Nil(t, convertConditionGroupToAPI(nil))
}

func TestHandleRulesExtra(t *testing.T) {
	srv := newTestServer()
	srv.SetRulesProvider(func() []correlator.Rule { return []correlator.Rule{ruleWithGroup()} })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	w := httptest.NewRecorder()
	srv.handleRules(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "rule-grp")

	// Wrong method.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/rules", nil)
	w = httptest.NewRecorder()
	srv.handleRules(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestExplainAlert(t *testing.T) {
	store := &mockAlertStore{
		alerts: []types.Alert{
			{ID: "alert-1", Timestamp: time.Now(), RuleID: "rule_001", Severity: types.SeverityCritical, PID: 1, Comm: "x", Message: "m"},
		},
		healthy: true,
	}

	t.Run("no store → 503", func(t *testing.T) {
		srv := newTestServer()
		w := httptest.NewRecorder()
		srv.explainAlert(w, httptest.NewRequest(http.MethodGet, "/x", nil), "alert-1")
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("no explainer → 501", func(t *testing.T) {
		srv := newTestServer()
		srv.SetAlertStore(store)
		w := httptest.NewRecorder()
		srv.explainAlert(w, httptest.NewRequest(http.MethodGet, "/x", nil), "alert-1")
		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	srv := newTestServer()
	srv.SetAlertStore(store)
	require.NoError(t, srv.SetupExplainer(""))

	t.Run("not found → 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.explainAlert(w, httptest.NewRequest(http.MethodGet, "/x", nil), "missing")
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("success → 200", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.explainAlert(w, httptest.NewRequest(http.MethodGet, "/x", nil), "alert-1")
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
