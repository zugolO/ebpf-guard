package correlator

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Item 8 волны 7 (№494): два правила event_type: cgroup_esc структурно инертны
// на ЛЮБОМ ядре — продюсера нет как такового. До 28.09.2026 их немота жила
// только прозой в attacks/silent-rules.txt и отсутствовала в машиночитаемом
// реестре. Теперь её печатает сам агент, и эта печать обязана иметь фикстуру.
func TestUnproducibleEventTypeRulesNamesCgroupEsc(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "container_escape_cgroup_migrate", EventType: types.EventCgroupEsc, Action: ActionAlert},
		{ID: "container_escape_cgroup_to_root", EventType: types.EventCgroupEsc, Action: ActionBlock},
		// Соседи по файлу, у которых продюсер есть: они обязаны остаться вне
		// списка, иначе предикат объявляет инертным весь каталог.
		{ID: "container_escape_cgroup_v1_release_agent", EventType: types.EventFileAccess, Action: ActionAlert},
		{ID: "privesc_cgroup_notify_on_release", EventType: types.EventFileAccess, Action: ActionAlert},
	})

	got := re.UnproducibleEventTypeRules()
	if len(got) != 2 {
		t.Fatalf("инертных правил %d, ожидалось 2: %+v", len(got), got)
	}
	if got[0].RuleID != "container_escape_cgroup_migrate" || got[1].RuleID != "container_escape_cgroup_to_root" {
		t.Errorf("порядок/состав не тот: %+v", got)
	}
	for _, r := range got {
		if r.EventType != "cgroup_esc" {
			t.Errorf("%s: event_type %q, ожидался cgroup_esc", r.RuleID, r.EventType)
		}
		if r.Reason == "" {
			t.Errorf("%s: причина инертности пуста — запись без доказательства это постоянная отговорка", r.RuleID)
		}
	}
}

// Ни одно правило на живой оси не вправе попасть в список: ложный «инертен»
// снимает с правила спрос и прячет настоящий регресс детекта.
func TestUnproducibleEventTypeRulesEmptyOnLiveAxes(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "a", EventType: types.EventSyscall, Action: ActionAlert},
		{ID: "b", EventType: types.EventFileAccess, Action: ActionAlert},
		{ID: "c", EventType: types.EventTCPConnect, Action: ActionAlert},
		{ID: "d", EventType: types.EventTLS, Action: ActionAlert},
		{ID: "e", EventType: types.EventDNS, Action: ActionAlert},
	})
	if got := re.UnproducibleEventTypeRules(); len(got) != 0 {
		t.Fatalf("живые оси объявлены инертными: %+v", got)
	}
}
