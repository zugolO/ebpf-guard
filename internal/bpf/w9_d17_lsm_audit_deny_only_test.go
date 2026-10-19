package bpf

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 9.1 / Д17 (волна 9): LSM-аудит пишет только отказы. Сторож по исходнику ядра:
// каждая запись в кольцо lsm_events с типом LSM_AUDIT несёт действие DENY, а
// хук task_kill (разрешает всегда) не резервирует кольцо вовсе и оставляет
// счётчик lsm_stats[TASK_KILL_ALLOW].
func TestW9_D17_LSMAuditRingCarriesDenialsOnly(t *testing.T) {
	src, err := os.ReadFile("../../bpf/lsm.bpf.c")
	require.NoError(t, err)
	text := string(src)

	// Ни одной записи аудита с действием AUDIT.
	assert.NotContains(t, text, "ae->action       = LSM_ACTION_AUDIT", "запись аудита без отказа вернулась в ядро")
	assert.NotRegexp(t, regexp.MustCompile(`ae->action\s*=\s*LSM_ACTION_AUDIT`), text)
	assert.GreaterOrEqual(t, strings.Count(text, "ae->action       = LSM_ACTION_DENY"), 3, "три отказных пути (file_open, два у socket_connect) остаются")

	// task_kill: счётчик есть, кольца нет.
	m := regexp.MustCompile(`(?s)int BPF_PROG\(lsm_task_kill,.*?\n\}`).FindString(text)
	require.NotEmpty(t, m, "в lsm.bpf.c нет lsm_task_kill")
	assert.Contains(t, m, "update_stat(LSM_STAT_TASK_KILL_ALLOW)", "на сигналы остался счётчик")
	assert.NotContains(t, m, "bpf_ringbuf_reserve", "task_kill не пишет в кольцо")
	assert.NotContains(t, m, "bpf_ringbuf_submit")
}
