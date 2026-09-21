package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.L, №420: у сайленса появилась продуктовая точка входа, и вопрос
// «каким именем аналитик его заводит» закрыт тем же резолвером, что у
// исключений (№413): имя из дашборда (решение Rego) разрешается в КАЖДОЕ
// базовое правило, и ответ перечисляет заведённые ключи поимённо —
// расширение на семью имени перестаёт быть молчаливым.

func silenceTestServer(t *testing.T, rules []correlator.Rule) *Server {
	t.Helper()
	srv := newTestServer()
	srv.SetRulesProvider(func() []correlator.Rule { return rules })
	srv.SetAlertSilencer(NewAlertSilencer())
	return srv
}

func postSilence(t *testing.T, srv *Server, req SilenceRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/silence", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAlertSilence(w, r)
	return w
}

func TestHandleAlertSilence_BaseNameSilencesRenamedAlert(t *testing.T) {
	srv := silenceTestServer(t, []correlator.Rule{{ID: "w63l2_base", EventType: types.EventSyscall}})

	w := postSilence(t, srv, SilenceRequest{RuleID: "w63l2_base", Severity: "warning", Duration: "5m", Reason: "fp"})
	require.Equal(t, http.StatusOK, w.Code)

	var resp SilenceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, []string{"w63l2_base:warning"}, resp.Keys)

	// Алерт после переименования Rego: RuleID уже чужой, base_rule_id — свой.
	renamed := types.Alert{
		RuleID:   "dga_domain",
		Severity: types.SeverityWarning,
		Details:  map[string]interface{}{types.BaseRuleIDDetailsKey: "w63l2_base"},
	}
	assert.True(t, srv.AlertSilencer().IsSilenced(renamed),
		"сайленс по БАЗОВОМУ имени обязан гасить алерт после переименования Rego")
}

func TestHandleAlertSilence_RenamedNameCoversEveryBaseRuleExplicitly(t *testing.T) {
	srv := silenceTestServer(t, []correlator.Rule{
		{ID: "w63l2_a", EventType: types.EventSyscall},
		{ID: "w63l2_b", EventType: types.EventSyscall},
		{ID: "w63l2_untouched", EventType: types.EventSyscall},
	})
	RecordAlertRuleIDRename("w63l2_a", "w63l2_shared")
	RecordAlertRuleIDRename("w63l2_b", "w63l2_shared")

	w := postSilence(t, srv, SilenceRequest{RuleID: "w63l2_shared", Severity: "critical", Duration: "5m"})
	require.Equal(t, http.StatusOK, w.Code)

	var resp SilenceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.ElementsMatch(t, []string{"w63l2_a:critical", "w63l2_b:critical"}, resp.Keys,
		"каждый заведённый ключ обязан быть НАЗВАН в ответе, а не применён молча")

	// Соседнее базовое правило, не делящее имя Rego, не тронуто.
	other := types.Alert{RuleID: "w63l2_untouched", Severity: types.SeverityCritical}
	assert.False(t, srv.AlertSilencer().IsSilenced(other))
}

func TestHandleAlertSilence_UnknownNameIs404AndNamesBothMisses(t *testing.T) {
	srv := silenceTestServer(t, []correlator.Rule{{ID: "w63l2_only", EventType: types.EventSyscall}})
	w := postSilence(t, srv, SilenceRequest{RuleID: "w63l2_nowhere", Duration: "1m"})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "unknown both as a loaded rule id and as a Rego-renamed name")
}

func TestHandleAlertSilence_ViewerForbiddenAndListing(t *testing.T) {
	srv := silenceTestServer(t, []correlator.Rule{{ID: "w63l2_base", EventType: types.EventSyscall}})

	body, _ := json.Marshal(SilenceRequest{RuleID: "w63l2_base", Duration: "1m"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/silence", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), tokenScopeKey{}, TokenScope{Role: RoleViewer}))
	w := httptest.NewRecorder()
	srv.handleAlertSilence(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)

	require.Equal(t, http.StatusOK, postSilence(t, srv, SilenceRequest{RuleID: "w63l2_base", Duration: "1m", Severity: "warning"}).Code)
	rg := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/silence", nil)
	wg := httptest.NewRecorder()
	srv.handleAlertSilence(wg, rg)
	require.Equal(t, http.StatusOK, wg.Code)
	var windows []SilenceWindowInfo
	require.NoError(t, json.Unmarshal(wg.Body.Bytes(), &windows))
	require.Len(t, windows, 1)
	assert.Equal(t, "w63l2_base:warning", windows[0].Key)
}

func TestHandleAlertSilence_DeleteLiftsWindow(t *testing.T) {
	srv := silenceTestServer(t, []correlator.Rule{{ID: "w63l2_base", EventType: types.EventSyscall}})
	require.Equal(t, http.StatusOK, postSilence(t, srv, SilenceRequest{RuleID: "w63l2_base", Duration: "5m", Severity: "warning"}).Code)

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/alerts/silence/w63l2_base:warning", nil)
	w := httptest.NewRecorder()
	srv.handleAlertSilenceByKey(w, r)
	require.Equal(t, http.StatusNoContent, w.Code)

	alert := types.Alert{RuleID: "w63l2_base", Severity: types.SeverityWarning}
	assert.False(t, srv.AlertSilencer().IsSilenced(alert))
}

// Инертность слоя: пока окон нет, IsSilenced не берёт мьютекс и не строит
// ключ — это условие, под которым слой вообще допущен на путь доставки.
func TestAlertSilencer_EmptyIsFreeAndFalse(t *testing.T) {
	sil := NewAlertSilencer()
	alert := types.Alert{RuleID: "anything", Severity: types.SeverityCritical}
	assert.False(t, sil.IsSilenced(alert))

	sil.Silence(SilenceKey("anything", types.SeverityCritical), 50*time.Millisecond, "r")
	assert.True(t, sil.IsSilenced(alert))
	assert.Equal(t, 0, sil.Cleanup(), "живое окно Cleanup не снимает")

	time.Sleep(60 * time.Millisecond)
	assert.False(t, sil.IsSilenced(alert), "истёкшее окно больше не гасит")
	assert.False(t, sil.IsSilenced(alert), "и счётчик активных окон вернулся к нулю — быстрый путь снова работает")
}
