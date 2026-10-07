package correlator

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.1, item 11. collectors.file_ops.drop_unresolved_rw роняет в ядре
// read/write, у которых fd не разрешился в путь (сокет, pipe, eventfd, файл,
// открытый до старта агента). Это безопасно ровно до тех пор, пока ни одно
// файловое правило не может сработать на таком событии. Гард держит это
// свойство на поставляемом наборе: новое правило на op read/write без
// предиката пути (например, только comm) покраснит здесь, а не тихо ослепнет
// на ноде с включённым сбросом.

// emptyPathReadWriteHits возвращает правила, срабатывающие на read/write с
// пустым путём. Перебираются comm/parent_comm/uid из литералов условий самого
// правила плюс фон, чтобы условие «comm in [...]» не прятало правило.
func emptyPathReadWriteHits(t *testing.T, rules []Rule) map[string]int {
	t.Helper()
	probe := NewRuleEngine(rules)
	hits := map[string]int{}
	for _, r := range rules {
		if r.EventType != types.EventFileAccess {
			continue
		}
		comms := []string{"k3s-server", "bash"}
		uids := []uint32{0, 1000}
		for _, c := range probe.getAllConditions(r) {
			switch c.Field {
			case "comm", "proc.comm", "parent_comm", "proc.parent_comm", "proc.pname":
				comms = append(comms, c.Values...)
			case "uid", "proc.uid", "user.uid":
				for _, v := range c.Values {
					if n, err := strconv.Atoi(v); err == nil {
						uids = append(uids, uint32(n))
					}
				}
			}
		}
		single := NewRuleEngine([]Rule{r})
		for _, op := range []uint8{1, 2} { // FILE_OP_READ, FILE_OP_WRITE
			for _, cm := range comms {
				for _, u := range uids {
					var cb [16]byte
					copy(cb[:], cm)
					e := types.Event{Type: types.EventFileAccess, PID: 4242, UID: u, Comm: cb, ParentComm: cb,
						File: &types.FileEvent{Op: op}}
					if len(single.Evaluate(e)) > 0 {
						hits[r.ID]++
					}
				}
			}
		}
	}
	return hits
}

func TestWave8_1_NoFileRuleFiresOnUnresolvedReadWrite(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	hits := emptyPathReadWriteHits(t, rules)
	assert.Empty(t, hits, "these file rules fire on read/write with an unresolved path; "+
		"collectors.file_ops.drop_unresolved_rw would blind them")
}

func TestWave8_1_UnresolvedRWGuardCanFail(t *testing.T) {
	// Мутация: правило на write только по comm обязано попасть в гард.
	mut := Rule{ID: "mut_comm_only_write", EventType: types.EventFileAccess,
		Severity: types.SeverityWarning, Action: ActionAlert,
		ConditionGroup: &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
			{Field: "file.op", Op: OpIn, Values: []string{"write"}},
			{Field: "proc.comm", Op: OpIn, Values: []string{"evil"}},
		}}}
	hits := emptyPathReadWriteHits(t, []Rule{mut})
	assert.Contains(t, hits, "mut_comm_only_write")
}
