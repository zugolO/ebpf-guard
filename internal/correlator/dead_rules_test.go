package correlator

import (
	"testing"

	"github.com/stretchr/testify/require"

	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func deadFixtureRules() []Rule {
	return []Rule{
		{ID: "live_sys", EventType: types.EventSyscall, Action: ActionAlert,
			Condition: RuleCondition{Field: "nr", Op: OpIn, Values: []string{"59"}}},
		{ID: "dead_nr", EventType: types.EventSyscall, Action: ActionAlert,
			Condition: RuleCondition{Field: "nr", Op: OpIn, Values: []string{"9999"}}},
		{ID: "live_file", EventType: types.EventFileAccess, Action: ActionAlert,
			Condition: RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc"}}},
		{ID: "dead_op", EventType: types.EventFileAccess, Action: ActionAlert,
			Condition: RuleCondition{Field: "op", Op: OpIn, Values: []string{"symlink"}}},
		{ID: "dead_proto", EventType: types.EventTCPConnect, Action: ActionAlert,
			Condition: RuleCondition{Field: "proto", Op: OpIn, Values: []string{"1"}}},
		{ID: "cloud_a", EventType: types.EventCloudAudit, Action: ActionAlert},
		{ID: "gpu_a", EventType: types.EventGPU, Action: ActionAlert},
		{ID: "iou_a", EventType: types.EventIOUring, Action: ActionAlert},
		{ID: "http_a", EventType: types.EventHTTPPlaintext, Action: ActionAlert},
		{ID: "cg_a", EventType: types.EventCgroupEsc, Action: ActionBlock},
		{ID: "tls_a", EventType: types.EventTLS, Action: ActionAlert},
	}
}

// Д19: полный список = все четыре оси; типы без продюсера по конфигу — тоже.
func TestDeadRulesNamesEveryAxis(t *testing.T) {
	re := NewRuleEngine(deadFixtureRules())
	off := map[types.EventType]string{
		types.EventCloudAudit: "no cloud collector enabled", types.EventIOUring: "iouring off",
		types.EventHTTPPlaintext: "http_plaintext off",
	}
	rep := re.DeadRules([]int{59, 1}, off)
	var ids []string
	for _, d := range rep.Dead {
		ids = append(ids, d.RuleID)
		require.NotEmpty(t, d.Reason, d.RuleID)
	}
	require.Equal(t, []string{"cg_a", "cloud_a", "dead_nr", "dead_op", "dead_proto", "gpu_a", "http_a", "iou_a"}, ids)
	require.Equal(t, 11, rep.Loaded)
	require.Equal(t, 3, rep.Live)
	require.Equal(t, map[string]int{DeadAxisEventType: 5, DeadAxisNr: 1, DeadAxisFileOp: 1, DeadAxisProto: 1}, rep.ByAxis)
}

// Продюсер включён по конфигу — правила его типа живые (gpu и cgroup_esc — нет:
// их нет в сборке, конфиг их не оживит).
func TestDeadRulesConfigEnablesProducer(t *testing.T) {
	re := NewRuleEngine(deadFixtureRules())
	rep := re.DeadRules(nil, nil)
	got := map[string]bool{}
	for _, d := range rep.Dead {
		got[d.RuleID] = true
	}
	require.True(t, got["gpu_a"] && got["cg_a"])
	for _, id := range []string{"cloud_a", "iou_a", "http_a", "dead_nr"} {
		require.False(t, got[id], id)
	}
}

// Отчёты покрытия считают только живые.
func TestLiveRulesDropsDead(t *testing.T) {
	rules := deadFixtureRules()
	re := NewRuleEngine(rules)
	rep := re.DeadRules([]int{59}, map[types.EventType]string{types.EventCloudAudit: "x"})
	live := LiveRules(rules, rep)
	require.Len(t, live, rep.Live)
	for _, r := range live {
		require.NotEqual(t, "cloud_a", r.ID)
		require.NotEqual(t, "gpu_a", r.ID)
	}
}

// На поставляемом наборе и конфиге стенда (cloud/iouring/http_plaintext
// выключены, фильтр ядра с набором по умолчанию) список — 57 правил.
func TestDeadRulesShippedSetOnStandConfig(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)
	off := map[types.EventType]string{
		types.EventCloudAudit: "x", types.EventIOUring: "x", types.EventHTTPPlaintext: "x",
	}
	rep := re.DeadRules(internalbpf.DefaultMonitoredSyscalls(), off)
	t.Logf("мёртвых %d из %d: %v", len(rep.Dead), rep.Loaded, rep.ByAxis)
	require.Equal(t, 57, len(rep.Dead), "ожидаемый список на конфиге стенда — 57 правил; ось: %v", rep.ByAxis)
	require.Equal(t, rep.Loaded-57, rep.Live)
}
