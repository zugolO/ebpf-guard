package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// №520 (02.10.2026). ransomware_mass_rename обещало проверку расширения
// .encrypted в proc.args, а условие матчило ЛЮБОЙ rename(2): 44 алерта за окно
// пары порции 4, 47 из 48 — pid 1 systemd, ~4/мин. Порог «20 за 10 с одним pid»
// разводит два случая. Тест держит оба конца: темп systemd не доходит до алерта
// никогда, цикл шифрования доходит на двадцатом переименовании.
func renameEvent(pid uint32, comm string, at time.Time) types.Event {
	ev := nrSyscall(82)
	ev.PID = pid
	copy(ev.Comm[:], comm)
	ev.Timestamp = uint64(at.UnixNano())
	return ev
}

func TestWave7MassRenameNeedsBurst(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)

	fired := func(ev types.Event) bool {
		for _, a := range re.Evaluate(ev) {
			if a.RuleID == "ransomware_mass_rename" {
				return true
			}
		}
		return false
	}

	// systemd: один rename раз в ~15 с (≈4/мин, темп пары порции 4), полчаса.
	base := time.Unix(1_900_000_000, 0)
	for i := 0; i < 120; i++ {
		assert.False(t, fired(renameEvent(1, "systemd", base.Add(time.Duration(i)*15*time.Second))),
			"темп systemd (4/мин) не должен давать ransomware_mass_rename (rename №%d)", i+1)
	}

	// Цикл шифрования: сто переименований за секунду одним python3.
	enc := base.Add(time.Hour)
	first := 0
	for i := 0; i < 100; i++ {
		if fired(renameEvent(4242, "python3", enc.Add(time.Duration(i)*10*time.Millisecond))) && first == 0 {
			first = i + 1
		}
	}
	assert.Equal(t, 20, first, "цикл переименований обязан дать алерт ровно на двадцатом вызове")

	// Девятнадцать быстрых переименований — ещё не «массовое».
	other := base.Add(2 * time.Hour)
	for i := 0; i < 19; i++ {
		assert.False(t, fired(renameEvent(5151, "python3", other.Add(time.Duration(i)*10*time.Millisecond))),
			"19 переименований ниже порога")
	}
}
