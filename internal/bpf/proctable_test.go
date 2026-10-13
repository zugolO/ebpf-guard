package bpf

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/zugolO/ebpf-guard/internal/procinfo"
)

// ptFakeMap — подставная карта: ключ pid → сырая запись.
type ptFakeMap struct {
	data   map[uint32]procRecRaw
	err    error // если задана — любой Lookup/Update возвращает её
	max    uint32
	hits   int
	perCPU map[uint32][]uint64
}

func (f *ptFakeMap) Lookup(key, valueOut interface{}) error {
	f.hits++
	if f.err != nil {
		return f.err
	}
	if pc, ok := valueOut.(*[]uint64); ok {
		v, ok := f.perCPU[key.(uint32)]
		if !ok {
			return ebpf.ErrKeyNotExist
		}
		*pc = v
		return nil
	}
	raw, ok := f.data[key.(uint32)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*(valueOut.(*procRecRaw)) = raw
	return nil
}

func (f *ptFakeMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	if f.err != nil {
		return f.err
	}
	if f.data == nil {
		f.data = map[uint32]procRecRaw{}
	}
	k := key.(uint32)
	if _, ok := f.data[k]; ok && flags == ebpf.UpdateNoExist {
		return ebpf.ErrKeyExist
	}
	f.data[k] = *(value.(*procRecRaw))
	return nil
}
func (f *ptFakeMap) MaxEntries() uint32 { return f.max }

func rawRec(ppid uint32, comm, fname string, start, exit uint64) procRecRaw {
	r := procRecRaw{PPID: ppid, StartBoottime: start, ExitTS: exit}
	copy(r.Comm[:], comm)
	copy(r.Filename[:], fname)
	return r
}

func newTestTable(live, exited *ptFakeMap, ttlNs, now uint64) *ProcTable {
	return &ProcTable{live: live, exited: exited, counters: &ptFakeMap{}, ttlNs: ttlNs, now: func() uint64 { return now }}
}

// Раскладка Go сверяется с ЗАГОЛОВКОМ ядра, а не с памятью: bpf/proctable.h — источник.
func TestW85_P1_RecordLayoutMatchesHeader(t *testing.T) {
	src, err := os.ReadFile("../../bpf/proctable.h")
	if err != nil {
		t.Fatal(err)
	}
	def := func(name string) int {
		m := regexp.MustCompile(`#define\s+` + name + `\s+(0x[0-9a-fA-F]+|\d+)`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("в proctable.h нет #define %s", name)
		}
		v, err := strconv.ParseInt(string(m[1]), 0, 64)
		if err != nil {
			t.Fatal(err)
		}
		return int(v)
	}
	var r procRecRaw
	if got := int(unsafe.Sizeof(r)); got != def("PROC_REC_SIZE") || got != procRecSize {
		t.Errorf("sizeof(procRecRaw) = %d, заголовок %d, константа %d", got, def("PROC_REC_SIZE"), procRecSize)
	}
	if binary.Size(r) != procRecSize {
		t.Errorf("binary.Size = %d: в procRecRaw неявные отступы или лишние поля", binary.Size(r))
	}
	for _, c := range []struct {
		name string
		off  uintptr
	}{
		{"PROC_REC_START_OFFSET", unsafe.Offsetof(r.StartBoottime)}, {"PROC_REC_EXIT_TS_OFFSET", unsafe.Offsetof(r.ExitTS)},
		{"PROC_REC_EXE_INO_OFFSET", unsafe.Offsetof(r.ExeIno)}, {"PROC_REC_PPID_OFFSET", unsafe.Offsetof(r.PPID)},
		{"PROC_REC_EXE_DEV_OFFSET", unsafe.Offsetof(r.ExeDev)}, {"PROC_REC_FLAGS_OFFSET", unsafe.Offsetof(r.Flags)},
		{"PROC_REC_COMM_OFFSET", unsafe.Offsetof(r.Comm)}, {"PROC_REC_FILENAME_OFFSET", unsafe.Offsetof(r.Filename)},
	} {
		if int(c.off) != def(c.name) {
			t.Errorf("%s: Go %d, заголовок %d", c.name, c.off, def(c.name))
		}
	}
	if def("PROC_COMM_LEN") != procRecCommLen || def("PROC_FNAME_LEN") != procRecFilenameLen {
		t.Error("длины comm/filename разошлись с заголовком")
	}
	if uint32(def("PROC_FLAG_EXEC")) != procinfo.FlagExec || uint32(def("PROC_FLAG_FNAME_TRUNC")) != procinfo.FlagFnameTrunc ||
		uint32(def("PROC_FLAG_SEEDED")) != procinfo.FlagSeeded {
		t.Error("флаги procinfo разошлись с заголовком")
	}
	// порядок enum proc_counter = procTableCounterNames
	en := regexp.MustCompile(`(?s)enum proc_counter \{(.*?)\};`).FindSubmatch(src)
	if en == nil {
		t.Fatal("нет enum proc_counter")
	}
	ids := regexp.MustCompile(`PC_([A-Z_]+)`).FindAllSubmatch(en[1], -1)
	want := []string{"FORK_OK", "FORK_FULL", "EXEC_UPDATED", "EXEC_CREATED", "EXEC_FULL", "EXIT_MOVED", "EXIT_NOREC", "EXITED_INSERT", "MAX"}
	if len(ids) != len(want) {
		t.Fatalf("enum proc_counter: %d значений, ждали %d", len(ids), len(want))
	}
	for i, id := range ids {
		if string(id[1]) != want[i] {
			t.Errorf("enum[%d] = PC_%s, ждали PC_%s", i, id[1], want[i])
		}
	}
	if len(procTableCounterNames) != len(want)-1 {
		t.Errorf("procTableCounterNames %d, enum %d", len(procTableCounterNames), len(want)-1)
	}
}

func TestW85_P1_LookupLiveThenExitedWithTTL(t *testing.T) {
	live := &ptFakeMap{data: map[uint32]procRecRaw{100: rawRec(1, "nginx", "/usr/sbin/nginx", 5, 0)}}
	exited := &ptFakeMap{data: map[uint32]procRecRaw{
		200: rawRec(100, "bash", "/bin/bash", 7, 1_000),
		300: rawRec(100, "curl", "", 8, 100),
	}}
	tb := newTestTable(live, exited, 500, 1_200) // TTL 500 нс, сейчас 1200
	if r, res := tb.Lookup(100); res != procinfo.Found || r.Comm != "nginx" || r.Filename != "/usr/sbin/nginx" || r.Exited() {
		t.Fatalf("живой: %+v %v", r, res)
	}
	if exited.hits != 0 {
		t.Fatal("живая запись нашлась, а в вышедшие всё равно ходили")
	}
	if r, res := tb.Lookup(200); res != procinfo.Found || r.Comm != "bash" || !r.Exited() {
		t.Fatalf("вышедший в пределах TTL: %+v %v", r, res)
	}
	if _, res := tb.Lookup(300); res != procinfo.Expired {
		t.Fatalf("вышедший за TTL: %v, want Expired", res)
	}
	if _, res := tb.Lookup(999); res != procinfo.Absent {
		t.Fatalf("нет нигде: %v, want Absent", res)
	}
	// ttl=0 — без ограничения
	tb0 := newTestTable(live, exited, 0, 1_000_000)
	if _, res := tb0.Lookup(300); res != procinfo.Found {
		t.Fatalf("TTL 0: %v", res)
	}
	// часы недоступны (0) — TTL не применяется, а не «всё истекло»
	tbc := newTestTable(live, exited, 500, 0)
	if _, res := tbc.Lookup(300); res != procinfo.Found {
		t.Fatalf("часов нет: %v", res)
	}
}

// Сбой чтения — Error и счётчик, а не «нет записи»: иначе авария карты читалась бы как вытеснение.
func TestW85_P1_LookupErrorIsNotAbsent(t *testing.T) {
	boom := errors.New("EPERM")
	tb := newTestTable(&ptFakeMap{err: boom}, &ptFakeMap{}, 0, 0)
	if _, res := tb.Lookup(5); res != procinfo.Error || tb.LookupErrors() != 1 {
		t.Fatalf("res=%v errors=%d", res, tb.LookupErrors())
	}
	tb2 := newTestTable(&ptFakeMap{}, &ptFakeMap{err: boom}, 0, 0)
	if _, res := tb2.Lookup(5); res != procinfo.Error || tb2.LookupErrors() != 1 {
		t.Fatalf("вышедшие: res=%v errors=%d", res, tb2.LookupErrors())
	}
	if _, res := tb.Lookup(0); res != procinfo.Absent {
		t.Fatal("pid 0 не ищется")
	}
}

func TestW85_P1_SeedDoesNotOverwriteKernelRecords(t *testing.T) {
	live := &ptFakeMap{data: map[uint32]procRecRaw{10: rawRec(1, "kernel-wrote", "/bin/x", 99, 0)}}
	tb := newTestTable(live, &ptFakeMap{}, 0, 0)
	seeded, existing, failed := tb.Seed([]SeedRecord{
		{PID: 10, PPID: 1, Comm: "seed-overwrite"}, {PID: 11, PPID: 1, StartBoottimeNs: 50, Comm: "systemd-journal-with-long-name"},
	})
	if seeded != 1 || existing != 1 || failed != 0 {
		t.Fatalf("seeded=%d existing=%d failed=%d", seeded, existing, failed)
	}
	if r, _ := tb.Lookup(10); r.Comm != "kernel-wrote" {
		t.Fatalf("засев затёр запись ядра: %q", r.Comm)
	}
	r, _ := tb.Lookup(11)
	if r.Flags&procinfo.FlagSeeded == 0 || r.Filename != "" || r.StartBoottimeNs != 50 || len(r.Comm) != 15 {
		t.Fatalf("засеянная запись: %+v", r)
	}
	tbFail := newTestTable(&ptFakeMap{err: errors.New("E2BIG")}, &ptFakeMap{}, 0, 0)
	if s, e, f := tbFail.Seed([]SeedRecord{{PID: 1}, {PID: 2}}); s != 0 || e != 0 || f != 2 {
		t.Fatalf("полная карта: %d %d %d", s, e, f)
	}
}

func TestW85_P1_CountersSumAcrossCPUs(t *testing.T) {
	pc := map[uint32][]uint64{}
	for i := range procTableCounterNames {
		pc[uint32(i)] = []uint64{uint64(i + 1), 10, 100}
	}
	tb := newTestTable(&ptFakeMap{}, &ptFakeMap{}, 0, 0)
	tb.counters = &ptFakeMap{perCPU: pc}
	got, err := tb.Counters()
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range procTableCounterNames {
		if want := uint64(i+1) + 110; got[name] != want {
			t.Errorf("%s = %d, want %d", name, got[name], want)
		}
	}
}

func TestW85_P1_KernelDevFromStat(t *testing.T) {
	// makedev(254, 1) в кодировке userspace — (major<<8)|minor
	if got, want := kernelDevFromStat(0xFE01), uint32(254<<20|1); got != want {
		t.Errorf("254:1 → %#x, want %#x", got, want)
	}
	// большой minor (nvme и т.п.): major 259, minor 0x1ab → new_encode_dev
	major, minor := uint64(259), uint64(0x1ab)
	enc := (minor & 0xff) | (major << 8) | ((minor &^ 0xff) << 12)
	if got, want := kernelDevFromStat(enc), uint32(259<<20|0x1ab); got != want {
		t.Errorf("259:0x1ab → %#x, want %#x", got, want)
	}
}

func TestW85_P1_ParseProcStat(t *testing.T) {
	// comm с пробелом и скобкой; поле 4 = ppid 77; поле 22 = 123456
	line := "4242 (we (ird) name) S 77 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000 100 18446744073709551615\n"
	comm, ppid, ticks, ok := parseProcStat(line)
	if !ok || comm != "we (ird) name" || ppid != 77 || ticks != 123456 {
		t.Fatalf("comm=%q ppid=%d ticks=%d ok=%v", comm, ppid, ticks, ok)
	}
	for _, bad := range []string{"", "1 (x)", "1 (x) S 2 3", "garbage", "1 (x) S notanumber 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21"} {
		if _, _, _, ok := parseProcStat(bad); ok {
			t.Errorf("%q разобрано", bad)
		}
	}
}

func TestW85_P1_ReadProcSeedFromFakeProc(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "realbinary")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	mk := func(pid, stat string, withExe bool) {
		d := filepath.Join(root, pid)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
		if withExe {
			if err := os.Symlink(exe, filepath.Join(d, "exe")); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("500", "500 (cron) S 1 500 500 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4000 0 0 0\n", true)
	mk("501", "501 (kthread) S 2 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0 0\n", false)
	mk("502", "garbage", true)
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil { // не число — пропуск
		t.Fatal(err)
	}
	recs, err := ReadProcSeed(root)
	if err != nil {
		t.Fatal(err)
	}
	by := map[uint32]SeedRecord{}
	for _, r := range recs {
		by[r.PID] = r
	}
	if len(by) != 2 {
		t.Fatalf("записей %d, want 2 (мусорный stat и не-pid пропущены): %+v", len(by), recs)
	}
	cron := by[500]
	st, _ := os.Stat(exe)
	if cron.Comm != "cron" || cron.PPID != 1 || cron.StartBoottimeNs != 4000*procClockTickNs || cron.ExeIno != uint64(st.Sys().(*syscall.Stat_t).Ino) || cron.ExePath != exe {
		t.Fatalf("cron: %+v", cron)
	}
	if k := by[501]; k.ExeIno != 0 || k.ExeDev != 0 || k.PPID != 2 {
		t.Fatalf("поток ядра без exe: %+v", k)
	}
}
