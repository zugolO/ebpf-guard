package bpf

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Список в Go и switch в ядре — одно и то же множество (сторож по исходнику).
func TestW85_F3_ServiceCmdsMirrorTheKernelSwitch(t *testing.T) {
	src, err := os.ReadFile("../../bpf/syscall.bpf.c")
	require.NoError(t, err)
	body := regexp.MustCompile(`(?s)bpf_cmd_is_service\(unsigned long cmd\)\s*\{(.*?)\n\}`).FindSubmatch(src)
	require.NotNil(t, body, "в syscall.bpf.c нет bpf_cmd_is_service")
	var got []uint32
	for _, m := range regexp.MustCompile(`case (\d+):`).FindAllSubmatch(body[1], -1) {
		n, err := strconv.ParseUint(string(m[1]), 10, 32)
		require.NoError(t, err)
		got = append(got, uint32(n))
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := append([]uint32(nil), SelfExcludedBPFServiceCmds...)
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	assert.Equal(t, want, got, "список служебных cmd в Go и в ядре разошёлся")
}

// Разрушительные команды никогда не служебные: пересечения нет.
func TestW85_F3_DestructiveCmdsAreNeverExcluded(t *testing.T) {
	svc := map[uint32]bool{}
	for _, c := range SelfExcludedBPFServiceCmds {
		svc[c] = true
	}
	for _, c := range BPFDestructiveCmds {
		assert.Falsef(t, svc[c], "cmd %d разрушительная, но в списке исключения", c)
	}
}

func TestW85_F3_SelfExcludedDelta(t *testing.T) {
	assert.Equal(t, uint64(5), selfExcludedDelta(10, 15))
	assert.Equal(t, uint64(0), selfExcludedDelta(15, 15))
	assert.Equal(t, uint64(3), selfExcludedDelta(15, 3), "карту пересоздали — вся новая сумма")
}

// Агент не отправляет себе exit исключённого вызова только при pid_is_agent() —
// иначе чужой процесс с magic в r9 прятал бы свой exit. Сторож по исходнику.
func TestW85_F3_ExitSideRequiresAgentPID(t *testing.T) {
	src, err := os.ReadFile("../../bpf/syscall.bpf.c")
	require.NoError(t, err)
	exit := regexp.MustCompile(`(?s)int trace_sys_exit.*`).FindString(string(src))
	require.NotEmpty(t, exit)
	i := regexp.MustCompile(`EG_SELF_EXCL_MAGIC && pid_is_agent\(\)`).FindStringIndex(exit)
	assert.NotNil(t, i, "exit-ветка самоисключения обязана проверять pid_is_agent()")
	enter := regexp.MustCompile(`(?s)int trace_sys_enter.*?int trace_sys_exit`).FindString(string(src))
	assert.Contains(t, enter, "bpf_cmd_is_service(ctx->args[0])")
	assert.Contains(t, enter, "pid_is_agent()")
}
