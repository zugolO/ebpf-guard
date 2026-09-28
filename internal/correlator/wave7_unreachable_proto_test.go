package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 7, item б1 (28.09.2026). Третье условие критерия волны 7 — «доля silent
// правил падает» — требует РАЗБОРА немоты по осям, а не одного решения на все
// 19 `fix-condition`: ось `nr` открывается конфигом и стоит измеримого шума, а
// ось `proto` не открывается ничем, потому что продюсера нет. Эти четыре
// правила переразмечены в класс «структурно инертны», и класс печатает АГЕНТ,
// а не проза ([[wave-criteria-need-an-emitter]]).

func TestWave7_UnreachableProtoRules_FlagsImpossibleProtos(t *testing.T) {
	mk := func(id string, field string, op RuleConditionOperator, values []string) Rule {
		return Rule{
			ID: id, EventType: types.EventTCPConnect, Severity: types.SeverityWarning, Action: ActionAlert,
			ConditionGroup: &RuleConditionGroup{
				Operator: "and",
				Conditions: []RuleCondition{
					{Field: "dport", Op: OpGreaterThan, Values: []string{"1024"}},
					{Field: field, Op: op, Values: values},
				},
			},
		}
	}
	engine := NewRuleEngine([]Rule{
		// Мертвы: ни одного производимого номера.
		mk("dead_icmp", "proto", OpIn, []string{"1"}),
		mk("dead_raw_set", "proto", OpIn, []string{"255", "41", "43", "47", "50", "51"}),
		// Живо, потому что 6 в наборе ЕСТЬ: смешанный набор не немой, он шумный.
		mk("live_mixed", "proto", OpIn, []string{"1", "6"}),
		// Живо: сам TCP.
		mk("live_tcp", "proto", OpEquals, []string{"6"}),
		// Дотовое имя оси обязано нормализоваться так же, как `syscall.nr` и
		// `file.op` (тот же приём, что вернул счёт немых syscall-правил 9 → 17).
		mk("dead_dotted_axis", "network.proto", OpEquals, []string{"47"}),
		// Короткий алиас `eq` — вторая форма записи того же условия.
		mk("dead_short_eq", "proto", "eq", []string{"1"}),
		// Правила БЕЗ условия на proto не трогаются: закрытый отказ.
		{ID: "no_proto_condition", EventType: types.EventTCPConnect, Severity: types.SeverityWarning, Action: ActionAlert,
			Condition: RuleCondition{Field: "dport", Op: OpIn, Values: []string{"4444"}}},
		// Чужой тип события с тем же полем не считается сетевым правилом.
		{ID: "other_event_type", EventType: types.EventSyscall, Severity: types.SeverityWarning, Action: ActionAlert,
			Condition: RuleCondition{Field: "proto", Op: OpIn, Values: []string{"1"}}},
	})

	assert.Equal(t, []string{"dead_dotted_axis", "dead_icmp", "dead_raw_set", "dead_short_eq"},
		engine.UnreachableProtoRules(),
		"немо только правило, у которого НИ ОДИН номер proto не производится ни одним хуком")
}

// Поставляемый набор правил — то же, что у трёх сестёр: состав зафиксирован,
// чтобы НОВОЕ правило с тем же дефектом ловил CI, а не следующий замер на ноде.
func TestWave7_UnreachableProtoRules_ShippedRuleset(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)

	unreachable := NewRuleEngine(rules).UnreachableProtoRules()
	t.Logf("network rules unreachable by proto (%d): %v", len(unreachable), unreachable)

	// Состав на 28.09.2026 (ревизия 7.0, docs/rules-audit-2026-09-27.csv,
	// dead_axis=proto). Правки условия здесь не будет: `proto` нельзя
	// «починить» переписыванием на 6 — правило об ICMP-туннеле стало бы
	// правилом о TCP и по-прежнему не ловило бы ICMP-туннель. Открывается это
	// только новым продюсером (хук на ICMP/GRE/raw), и это решение владельца с
	// измеренной ценой шума, а не механическая правка.
	assert.ElementsMatch(t, []string{
		"c2_icmp_large_payload",
		"netintr_gre_tunnel",
		"netintr_icmp_outbound_large",
		"netintr_raw_socket_connection",
	}, unreachable,
		"состав правил, немых по оси proto, изменился: внести новое сюда после решения, что с ним делать, либо убрать починенное")
}

// Список производимых номеров не вправе быть длиннее того, что пишет продюсер:
// добавить в него значение — значит объявить хук, которого нет, и тем СНЯТЬ
// немоту с правила, не сняв её с прибора. Сторож держит связь списка с
// bpf/network.bpf.c числом, а не комментарием.
func TestWave7_ProducibleNetworkProtos_MatchesProducer(t *testing.T) {
	assert.Equal(t, []string{"6"}, producibleNetworkProtos,
		"bpf/network.bpf.c пишет только IPPROTO_TCP (четыре присваивания); расширять список можно ТОЛЬКО вместе с новым хуком")
}
