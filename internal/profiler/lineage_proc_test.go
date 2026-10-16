package profiler

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// Волна 8.7, П7: разбор /proc/<pid>/status по первым 512 байтам без Split/Fields.
func TestParseProcStatus(t *testing.T) {
	cases := []struct {
		name string
		in   string
		comm string
		ppid uint32
	}{
		{"обычный", "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t10\nNgid:\t0\nPid:\t10\nPPid:\t4\nTracerPid:\t0\n", "bash", 4},
		{"pid 1: PPid 0", "Name:\tsystemd\nPid:\t1\nPPid:\t0\n", "systemd", 0},
		{"comm с пробелом — первое слово, как у Fields", "Name:\tWeb Content\nPPid:\t77\n", "Web", 77},
		{"нет PPid", "Name:\tx\n", "x", 0},
		{"нет Name", "PPid:\t5\n", "", 5},
		{"пусто", "", "", 0},
		{"обрыв без перевода строки", "Name:\tabc\nPPid:\t9", "abc", 9},
		{"мусорный PPid", "Name:\tabc\nPPid:\tzzz\n", "abc", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comm, ppid := parseProcStatus([]byte(c.in))
			require.Equal(t, c.comm, comm)
			require.Equal(t, c.ppid, ppid)
		})
	}
}

// Комм живёт в кэшах цепочек: он не должен быть подстрокой буфера чтения.
func TestParseProcStatusCommIsACopy(t *testing.T) {
	b := []byte("Name:\tbash\nPPid:\t4\n")
	comm, _ := parseProcStatus(b)
	for i := range b {
		b[i] = 'X'
	}
	require.Equal(t, "bash", comm)
}

// Статус настоящего процесса (на мак /proc нет — тест пропускается).
func TestReadProcStatusSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("нет /proc")
	}
	comm, ppid := readProcStatus(uint32(os.Getpid()))
	require.NotEmpty(t, comm)
	require.Equal(t, uint32(os.Getppid()), ppid)
}

// Неважно, где обрезается буфер: Name: и PPid: лежат в начале и укладываются в 512 байт.
func TestProcStatusFitsBuffer(t *testing.T) {
	long := "Name:\tkworker/u16:3-ev\nUmask:\t0000\nState:\tI (idle)\nTgid:\t1234567\nNgid:\t0\nPid:\t1234567\nPPid:\t2\nTracerPid:\t0\n"
	require.Less(t, len(long), procStatusBufSize)
	comm, ppid := parseProcStatus([]byte(long))
	require.Equal(t, "kworker/u16:3-ev", comm)
	require.Equal(t, uint32(2), ppid, strconv.Itoa(int(ppid)))
}

// buildChainFromProc: порядок «от старшего предка к процессу» и глубина сохранены после
// перехода с prepend на append+разворот (цепочка собрана из кэша, /proc не нужен).
func TestBuildChainFromProcOrderAndDepth(t *testing.T) {
	lt := NewLineageTracker(LineageConfig{}, nil)
	put := func(pid, ppid uint32, comm string) {
		s := lt.shardFor(pid)
		s.mu.Lock()
		s.procCache[pid] = &procEntry{comm: comm, ppid: ppid}
		s.mu.Unlock()
	}
	put(50, 40, "curl")
	put(40, 30, "bash")
	put(30, 20, "nginx")
	put(20, 10, "containerd-shim")
	put(10, 1, "containerd")

	got := lt.buildChainFromProc(50, 8)
	var comms []string
	for _, n := range got {
		comms = append(comms, n.Comm)
	}
	require.Equal(t, []string{"containerd", "containerd-shim", "nginx", "bash", "curl"}, comms)
	require.Equal(t, uint32(10), got[0].PID)
	require.Equal(t, uint32(50), got[len(got)-1].PID)

	short := lt.buildChainFromProc(50, 3)
	require.Len(t, short, 3)
	require.Equal(t, "nginx", short[0].Comm, "при обрезке по глубине остаются ближайшие предки")
	require.Equal(t, "curl", short[2].Comm)
	require.Nil(t, lt.buildChainFromProc(50, 0))
}
