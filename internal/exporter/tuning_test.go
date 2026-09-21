package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"gopkg.in/yaml.v3"
)

// TestCommFieldForEventType pins the axis lookup to the LOADER's allowlists
// (wave 6.3.L.1, item 1, №422): the exporter no longer keeps its own switch of
// three event types, so every type whose rules may say comm/proc.comm can be
// narrowed by comm — DNS and TLS among them, which the old copy refused.
func TestCommFieldForEventType(t *testing.T) {
	field, ok := correlator.CommFieldForEventType(types.EventSyscall)
	assert.True(t, ok)
	assert.Equal(t, "proc.comm", field)

	field, ok = correlator.CommFieldForEventType(types.EventTCPConnect)
	assert.True(t, ok)
	assert.Equal(t, "proc.comm", field)

	field, ok = correlator.CommFieldForEventType(types.EventFileAccess)
	assert.True(t, ok)
	assert.Equal(t, "proc.comm", field)

	// The two types the old hard-coded switch refused although their rules
	// accept proc.comm — this is the half of №422 that was a stale copy.
	field, ok = correlator.CommFieldForEventType(types.EventDNS)
	assert.True(t, ok)
	assert.Equal(t, "proc.comm", field)

	_, ok = correlator.CommFieldForEventType(types.EventTLS)
	assert.True(t, ok)

	// Cloud-audit events carry no process at all: there is nothing to forge a
	// comm from, and the refusal must say so rather than emit a dead condition.
	_, ok = correlator.CommFieldForEventType(types.EventCloudAudit)
	assert.False(t, ok)
}

func TestBuildException(t *testing.T) {
	t.Run("simple comm condition", func(t *testing.T) {
		exc, refusal := buildException(TuningExceptionRequest{Name: "fp1", Comm: "systemd"}, correlator.Rule{ID: "r", EventType: types.EventSyscall})
		require.Nil(t, refusal)
		assert.Equal(t, "fp1", exc.Name)
		assert.Nil(t, exc.ConditionGroup)
		assert.Equal(t, "proc.comm", exc.Condition.Field)
		assert.Equal(t, correlator.OpEquals, exc.Condition.Op)
		assert.Equal(t, []string{"systemd"}, exc.Condition.Values)
	})

	t.Run("comm + path prefix on file rule", func(t *testing.T) {
		exc, refusal := buildException(TuningExceptionRequest{Name: "fp2", Comm: "app", PathPrefix: "/tmp/"}, correlator.Rule{ID: "r", EventType: types.EventFileAccess})
		require.Nil(t, refusal)
		require.NotNil(t, exc.ConditionGroup)
		assert.Equal(t, "and", exc.ConditionGroup.Operator)
		require.Len(t, exc.ConditionGroup.Conditions, 2)
		assert.Equal(t, "proc.comm", exc.ConditionGroup.Conditions[0].Field)
		assert.Equal(t, "file.path", exc.ConditionGroup.Conditions[1].Field)
		assert.Equal(t, correlator.OpPrefix, exc.ConditionGroup.Conditions[1].Op)
	})

	t.Run("path prefix ignored on non-file rule", func(t *testing.T) {
		exc, refusal := buildException(TuningExceptionRequest{Name: "fp3", Comm: "app", PathPrefix: "/tmp/"}, correlator.Rule{ID: "r", EventType: types.EventSyscall})
		require.Nil(t, refusal)
		assert.Nil(t, exc.ConditionGroup)
	})

	// №422: a synthetic rule (anomaly_detection — the single largest source of
	// volume) refuses comm, but the refusal must NAME the axes it does take,
	// and the same request with one of those axes must succeed.
	t.Run("synthetic rule refuses comm and names the identity axes", func(t *testing.T) {
		_, refusal := buildException(TuningExceptionRequest{Name: "fp5", Comm: "app"}, correlator.Rule{ID: "anomaly_detection", Synthetic: true})
		require.NotNil(t, refusal)
		assert.Equal(t, "synthetic_rule_needs_identity_axis", refusal.Reason)
		assert.True(t, refusal.Synthetic)
		assert.Contains(t, refusal.SupportedAxes, "proc.exe_path")
	})

	t.Run("synthetic rule narrows on the identity axis", func(t *testing.T) {
		exc, refusal := buildException(
			TuningExceptionRequest{Name: "fp6", Axis: "proc.exe_path", AxisValue: "/usr/bin/containerd"},
			correlator.Rule{ID: "anomaly_detection", Synthetic: true})
		require.Nil(t, refusal)
		assert.Equal(t, "proc.exe_path", exc.Condition.Field)
		assert.Equal(t, []string{"/usr/bin/containerd"}, exc.Condition.Values)
	})

	t.Run("event type without a comm field names the axes", func(t *testing.T) {
		_, refusal := buildException(TuningExceptionRequest{Name: "fp7", Comm: "app"}, correlator.Rule{ID: "r", EventType: types.EventCloudAudit})
		require.NotNil(t, refusal)
		assert.Equal(t, "event_type_has_no_comm_field", refusal.Reason)
		assert.NotEmpty(t, refusal.SupportedAxes)
	})
}

func rulesProviderWithSyscallRule(ruleID string) func() []correlator.Rule {
	return func() []correlator.Rule {
		return []correlator.Rule{{ID: ruleID, EventType: types.EventSyscall}}
	}
}

func TestHandleTuningExceptions(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		srv := newTestServer()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tuning/exceptions", nil)
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("viewer role forbidden", func(t *testing.T) {
		srv := newTestServer()
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "n", Comm: "c"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		ctx := context.WithValue(req.Context(), tokenScopeKey{}, TokenScope{Role: RoleViewer})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("missing required fields", func(t *testing.T) {
		srv := newTestServer()
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("rule not found", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(rulesProviderWithSyscallRule("other_rule"))
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "n", Comm: "c"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// №422: a DNS rule IS narrowable by comm — the old three-type switch said
	// otherwise and answered 400 to the analyst.
	t.Run("dns rule is narrowable by comm", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(func() []correlator.Rule {
			return []correlator.Rule{{ID: "r1", EventType: types.EventDNS}}
		})
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "n", Comm: "c"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "proc.comm", resp.Axes["r1"])
	})

	// The live shape of №422: the analyst posts the name the dashboard shows,
	// it resolves to the synthetic anomaly_detection, and the answer must be a
	// 422 that names the axis — never the bare 400 that ended the trail.
	t.Run("synthetic rule answers 422 and names the axis", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(func() []correlator.Rule {
			return []correlator.Rule{{ID: "anomaly_detection", Synthetic: true}}
		})
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "anomaly_detection", Name: "n", Comm: "c"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusUnprocessableEntity, w.Code)

		var refusal TuningAxisRefusal
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refusal))
		assert.Equal(t, "synthetic_rule_needs_identity_axis", refusal.Reason)
		assert.Equal(t, "anomaly_detection", refusal.RuleID)
		assert.Contains(t, refusal.SupportedAxes, "proc.exe_path")

		// …and the axis it named actually works, on the same endpoint.
		body2, _ := json.Marshal(TuningExceptionRequest{
			RuleID: "anomaly_detection", Name: "n",
			Axis: "proc.exe_path", AxisValue: "/usr/bin/containerd",
		})
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body2))
		w2 := httptest.NewRecorder()
		srv.handleTuningExceptions(w2, req2)
		require.Equal(t, http.StatusOK, w2.Code)
		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
		assert.Equal(t, "proc.exe_path", resp.Axes["anomaly_detection"])
		assert.Contains(t, resp.YAML, "/usr/bin/containerd")
	})

	t.Run("unknown axis is a 400", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(rulesProviderWithSyscallRule("r1"))
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "n", Axis: "comm", AxisValue: "bash"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("snippet only, not persisted", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(rulesProviderWithSyscallRule("r1"))
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "fp_test", Comm: "bash"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.Persisted)
		assert.Contains(t, resp.YAML, "r1")
		assert.Contains(t, resp.YAML, "bash")
	})

	t.Run("persist writes and validates against overlay file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "local-tuning.yaml")

		srv := newTestServer()
		srv.SetRulesProvider(rulesProviderWithSyscallRule("r1"))
		srv.SetLocalTuningPath(path)

		reloaded := false
		srv.SetRulesReloadHandler(func() error {
			reloaded = true
			return nil
		})

		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "fp_test", Comm: "bash", Persist: true})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.Persisted)
		assert.True(t, reloaded)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var overlay correlator.TuningOverlay
		require.NoError(t, yaml.Unmarshal(data, &overlay))
		require.Len(t, overlay.Overlays, 1)
		assert.Equal(t, "r1", overlay.Overlays[0].RuleID)
		require.Len(t, overlay.Overlays[0].Exceptions, 1)
		assert.Equal(t, "fp_test", overlay.Overlays[0].Exceptions[0].Name)

		// A second exception for the same rule appends rather than overwrites.
		body2, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "fp_test2", Comm: "curl", Persist: true})
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body2))
		w2 := httptest.NewRecorder()
		srv.handleTuningExceptions(w2, req2)
		require.Equal(t, http.StatusOK, w2.Code)

		data2, err := os.ReadFile(path)
		require.NoError(t, err)
		var overlay2 correlator.TuningOverlay
		require.NoError(t, yaml.Unmarshal(data2, &overlay2))
		require.Len(t, overlay2.Overlays, 1)
		assert.Len(t, overlay2.Overlays[0].Exceptions, 2)
	})

	t.Run("persist without configured path returns persisted=false", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(rulesProviderWithSyscallRule("r1"))

		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "r1", Name: "fp_test", Comm: "bash", Persist: true})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.Persisted)
	})

	t.Run("invalid request body", func(t *testing.T) {
		srv := newTestServer()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader([]byte("not json")))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	// №413 (wave 6.3.L, item 1): the analyst only ever sees the Rego-renamed
	// name, which never appears in rules/*.yaml — resolving it through the
	// reverse rename index is what makes the exception API usable at all for
	// a renamed alert.
	t.Run("renamed rule_id resolves to its base rule via rename index", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(rulesProviderWithSyscallRule("w63l1_base"))
		RecordAlertRuleIDRename("w63l1_base", "w63l1_renamed")

		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "w63l1_renamed", Name: "fp_test", Comm: "bash"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp.YAML, "w63l1_base")
	})

	// A renamed name shared by several base rules (dga_domain live pattern)
	// generates an exception against every one of them, not just the first.
	t.Run("renamed rule_id shared by several base rules resolves to all of them", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(func() []correlator.Rule {
			return []correlator.Rule{
				{ID: "w63l1_base_a", EventType: types.EventSyscall},
				{ID: "w63l1_base_b", EventType: types.EventSyscall},
			}
		})
		RecordAlertRuleIDRename("w63l1_base_a", "w63l1_shared")
		RecordAlertRuleIDRename("w63l1_base_b", "w63l1_shared")

		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "w63l1_shared", Name: "fp_test", Comm: "bash"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		var overlay correlator.TuningOverlay
		require.NoError(t, yaml.Unmarshal([]byte(resp.YAML), &overlay))
		require.Len(t, overlay.Overlays, 2)
		gotIDs := []string{overlay.Overlays[0].RuleID, overlay.Overlays[1].RuleID}
		assert.ElementsMatch(t, []string{"w63l1_base_a", "w63l1_base_b"}, gotIDs)
	})

	// Ревизия волны 6.3.L: два пространства имён (YAML-id и имена решений
	// Rego) не разделены по построению — имя, которое одновременно и
	// загруженное правило, и цель переименования, обязано разрешаться в ОБА,
	// иначе базовое правило, которое реально сработало, останется нетронутым.
	t.Run("name that is both a loaded rule and a rename target resolves to both", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(func() []correlator.Rule {
			return []correlator.Rule{
				{ID: "w63l1_collide", EventType: types.EventSyscall},
				{ID: "w63l1_collide_base", EventType: types.EventSyscall},
			}
		})
		RecordAlertRuleIDRename("w63l1_collide_base", "w63l1_collide")

		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "w63l1_collide", Name: "fp_test", Comm: "bash"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		var overlay correlator.TuningOverlay
		require.NoError(t, yaml.Unmarshal([]byte(resp.YAML), &overlay))
		require.Len(t, overlay.Overlays, 2)
		assert.ElementsMatch(t, []string{"w63l1_collide", "w63l1_collide_base"},
			[]string{overlay.Overlays[0].RuleID, overlay.Overlays[1].RuleID})
	})

	// Персист разделённого имени — ОДНА запись файла на весь запрос: оба
	// базовых правила оказываются в оверлее, перезагрузка правил зовётся один
	// раз, половинчатого применения не бывает.
	t.Run("persist of a split name writes every base rule in one pass", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "local-tuning.yaml")

		srv := newTestServer()
		srv.SetRulesProvider(func() []correlator.Rule {
			return []correlator.Rule{
				{ID: "w63l1_p_a", EventType: types.EventSyscall},
				{ID: "w63l1_p_b", EventType: types.EventSyscall},
			}
		})
		srv.SetLocalTuningPath(path)
		reloads := 0
		srv.SetRulesReloadHandler(func() error { reloads++; return nil })

		RecordAlertRuleIDRename("w63l1_p_a", "w63l1_p_shared")
		RecordAlertRuleIDRename("w63l1_p_b", "w63l1_p_shared")

		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "w63l1_p_shared", Name: "fp_test", Comm: "bash", Persist: true})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp TuningExceptionResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.Persisted)
		assert.Equal(t, 1, reloads, "одна перезагрузка правил на запрос, а не по одной на каждое базовое правило")

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var overlay correlator.TuningOverlay
		require.NoError(t, yaml.Unmarshal(data, &overlay))
		require.Len(t, overlay.Overlays, 2)
		assert.ElementsMatch(t, []string{"w63l1_p_a", "w63l1_p_b"},
			[]string{overlay.Overlays[0].RuleID, overlay.Overlays[1].RuleID})
	})

	// A name unknown as either a loaded rule id or a rename target still 404s.
	t.Run("rule_id unknown as both base and renamed name 404s", func(t *testing.T) {
		srv := newTestServer()
		srv.SetRulesProvider(rulesProviderWithSyscallRule("other_rule"))
		body, _ := json.Marshal(TuningExceptionRequest{RuleID: "w63l1_unknown", Name: "n", Comm: "c"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tuning/exceptions", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.handleTuningExceptions(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "unknown both as a loaded rule id and as a Rego-renamed name")
	})
}
