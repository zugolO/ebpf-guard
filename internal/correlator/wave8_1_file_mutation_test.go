package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.1, item 7: у оси file.op появился продюсер unlink/rename/truncate/
// rmdir (FILE_OP_* 4..7 в bpf/common.h). Четыре правила, которые
// UnreachableFileOpRules печатал немыми с волны 6.2.2, теперь достижимы, и
// исключение журналирующих демонов ноды обязано стоять на образе, а не на comm.

const (
	w81OpUnlink   uint8 = 4
	w81OpRename   uint8 = 5
	w81OpTruncate uint8 = 6
	w81OpRmdir    uint8 = 7
)

var w81LogRules = []string{
	"evasion_log_clear",
	"defense_evasion_journald_log_clear",
	"ransomware_log_wipe",
	"impact_mass_file_deletion_critical",
}

func TestWave8_1_FileOpNamesMatchBPF(t *testing.T) {
	// Порядок обязан совпадать с FILE_OP_* в bpf/common.h: расхождение
	// переименует операцию, а не сломает сборку.
	assert.Equal(t, "unlink", fileOpNames[w81OpUnlink])
	assert.Equal(t, "rename", fileOpNames[w81OpRename])
	assert.Equal(t, "truncate", fileOpNames[w81OpTruncate])
	assert.Equal(t, "rmdir", fileOpNames[w81OpRmdir])
}

func w81Engine(t *testing.T) *RuleEngine {
	t.Helper()
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	return NewRuleEngine(rules)
}

func w81FileEvent(pid uint32, comm, path string, op uint8) types.Event {
	var c [16]byte
	copy(c[:], comm)
	fe := &types.FileEvent{Op: op}
	copy(fe.Filename[:], path)
	return types.Event{Type: types.EventFileAccess, PID: pid, UID: 0, Comm: c, File: fe}
}

func w81Fired(alerts []types.Alert) map[string]bool {
	out := map[string]bool{}
	for _, a := range alerts {
		out[a.RuleID] = true
	}
	return out
}

func TestWave8_1_LogWipeRulesFireOnRm(t *testing.T) {
	w624WithExe(t, "rm")
	engine := w81Engine(t)
	fired := w81Fired(engine.Evaluate(w81FileEvent(4242, "rm", "/var/log/auth.log", w81OpUnlink)))
	for _, id := range w81LogRules {
		assert.Truef(t, fired[id], "%s обязано сработать на rm /var/log/auth.log", id)
	}
	fired = w81Fired(engine.Evaluate(w81FileEvent(4242, "truncate", "/var/log/syslog", w81OpTruncate)))
	assert.True(t, fired["evasion_log_clear"], "truncate журнала")
	assert.True(t, fired["ransomware_log_wipe"], "truncate журнала от root")
	fired = w81Fired(engine.Evaluate(w81FileEvent(4242, "mv", "/var/log/auth.log", w81OpRename)))
	assert.True(t, fired["evasion_log_clear"], "rename журнала")
	fired = w81Fired(engine.Evaluate(w81FileEvent(4242, "rm", "/etc/cron.d", w81OpRmdir)))
	assert.True(t, fired["impact_mass_file_deletion_critical"], "rmdir в /etc")
}

func TestWave8_1_JournaldByImageSuppressed(t *testing.T) {
	// Настоящий journald: образ /usr/lib/systemd/systemd-journald, comm обрезан
	// до 15 байт. Список comm в условиях двух правил его не ловил — держит
	// именованное исключение log-daemon-image.
	w624WithExe(t, "systemd-journal")
	engine := w81Engine(t)
	fired := w81Fired(engine.Evaluate(w81FileEvent(4242, "systemd-journal",
		"/var/log/journal/0123/system.journal", w81OpTruncate)))
	for _, id := range w81LogRules {
		assert.Falsef(t, fired[id], "%s не должно срабатывать на ftruncate journald из его образа", id)
	}
}

func TestWave8_1_JournaldSpoofFires(t *testing.T) {
	// Тот же comm из чужого образа — подделка имени, исключение не применяется.
	w624WithExe(t, "systemd-journal")
	engine := w81Engine(t)
	fired := w81Fired(engine.Evaluate(w81FileEvent(w624SpoofPID, "systemd-journal",
		"/var/log/auth.log", w81OpUnlink)))
	assert.True(t, fired["ransomware_log_wipe"], "подделка comm journald обязана сработать")
	assert.True(t, fired["impact_mass_file_deletion_critical"], "подделка comm journald обязана сработать")
}
