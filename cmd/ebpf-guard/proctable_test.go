package main

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/procinfo"
	"github.com/zugolO/ebpf-guard/internal/profiler"
)

type fakeProcTable struct {
	recs   map[uint32]procinfo.Record
	seeded []internalbpf.SeedRecord
	closed bool
}

func (f *fakeProcTable) Lookup(pid uint32) (procinfo.Record, procinfo.Result) {
	r, ok := f.recs[pid]
	if !ok {
		return procinfo.Record{}, procinfo.Absent
	}
	return r, procinfo.Found
}
func (f *fakeProcTable) Counters() (map[string]uint64, error) {
	return map[string]uint64{"fork_ok": 7}, nil
}
func (f *fakeProcTable) LookupErrors() uint64       { return 0 }
func (f *fakeProcTable) Capacity() (uint32, uint32) { return 16384, 16384 }
func (f *fakeProcTable) Seed(recs []internalbpf.SeedRecord) (int, int, int) {
	f.seeded = recs
	return len(recs), 0, 0
}
func (f *fakeProcTable) Close() error { f.closed = true; return nil }

func ptState(s string) float64 {
	return testutil.ToFloat64(internalbpf.ProcTableStateGauge(s))
}

func ptConfig() *config.Config {
	cfg := &config.Config{}
	cfg.BPF.ProcTable = config.ProcTableConfig{Enabled: true, LiveEntries: 16384, ExitedEntries: 16384}
	cfg.Profiler.Lineage.TTL = 300
	return cfg
}

func ptTracker() *profiler.LineageTracker {
	return profiler.NewLineageTracker(profiler.LineageConfig{Enabled: true, MaxDepth: 8}, slog.Default())
}

func neverOpen(t *testing.T) procTableOpener {
	return func(internalbpf.ProcTableConfig) (procTableHandle, error) {
		t.Fatal("таблица открыта там, где её открывать нельзя")
		return nil, nil
	}
}

func noSeed() ([]internalbpf.SeedRecord, error) { return nil, nil }

func TestW85_P1_StartProcTable_OffStatesLeaveTheTrackerOnTheOldPath(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*config.Config, *bool)
		state  string
		noLT   bool
	}{
		{"dry-run", func(_ *config.Config, d *bool) { *d = true }, internalbpf.ProcTableOffDryRun, false},
		{"config", func(c *config.Config, _ *bool) { c.BPF.ProcTable.Enabled = false }, internalbpf.ProcTableOffConfig, false},
		{"no-lineage", func(*config.Config, *bool) {}, internalbpf.ProcTableOffNoLineage, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, dry := ptConfig(), false
			c.mutate(cfg, &dry)
			lt := ptTracker()
			if c.noLT {
				lt = profiler.NewLineageTracker(profiler.LineageConfig{Enabled: false}, slog.Default())
			}
			closeFn := startProcTable(cfg, lt, dry, neverOpen(t), noSeed, nil, nil)
			closeFn()
			if lt.HasProcSource() {
				t.Fatal("трекер переключён на таблицу в состоянии off_*")
			}
			if ptState(c.state) != 1 || ptState(internalbpf.ProcTableActive) != 0 {
				t.Fatalf("состояние: %s=%v active=%v", c.state, ptState(c.state), ptState(internalbpf.ProcTableActive))
			}
		})
	}
}

func TestW85_P1_StartProcTable_LoadFailureKeepsTheFallback(t *testing.T) {
	lt := ptTracker()
	closeFn := startProcTable(ptConfig(), lt, false, func(internalbpf.ProcTableConfig) (procTableHandle, error) {
		return nil, errors.New("verifier: permission denied")
	}, noSeed, nil, nil)
	closeFn()
	if lt.HasProcSource() || ptState(internalbpf.ProcTableOffLoadFailed) != 1 {
		t.Fatalf("has=%v state=%v", lt.HasProcSource(), ptState(internalbpf.ProcTableOffLoadFailed))
	}
}

func TestW85_P1_StartProcTable_ActiveSeedsThenSwitchesAndClosesBack(t *testing.T) {
	ft := &fakeProcTable{recs: map[uint32]procinfo.Record{
		100: {PID: 100, PPID: 1, Comm: "nginx", StartBoottimeNs: 1},
		101: {PID: 101, PPID: 100, Comm: "bash", StartBoottimeNs: 2},
	}}
	lt := ptTracker()
	var gotCfg internalbpf.ProcTableConfig
	reg := prometheus.NewRegistry()
	imgs := procinfo.NewImageCache(16)
	closeFn := startProcTable(ptConfig(), lt, false, func(c internalbpf.ProcTableConfig) (procTableHandle, error) {
		gotCfg = c
		return ft, nil
	}, func() ([]internalbpf.SeedRecord, error) {
		return []internalbpf.SeedRecord{{PID: 100, PPID: 1, Comm: "nginx", ExeDev: 7, ExeIno: 99, ExePath: "/usr/sbin/nginx"}}, nil
	}, imgs, reg)
	if gotCfg.LiveEntries != 16384 || gotCfg.ExitedEntries != 16384 || gotCfg.TTL.Seconds() != 300 {
		t.Fatalf("параметры загрузки: %+v", gotCfg)
	}
	if len(ft.seeded) != 1 {
		t.Fatalf("засев не вызван: %+v", ft.seeded)
	}
	if !lt.HasProcSource() || ptState(internalbpf.ProcTableActive) != 1 {
		t.Fatal("таблица не включена")
	}
	if imgs.Len() != 1 {
		t.Fatalf("засев не наполнил кэш образов: %d", imgs.Len())
	}
	tree := lt.GetProcessTree(101)
	if len(tree) != 2 || tree[0].Comm != "nginx" || tree[1].Comm != "bash" {
		t.Fatalf("цепочка из таблицы: %+v", tree)
	}
	// метрики таблицы зарегистрированы и читаются
	if n, err := testutil.GatherAndCount(reg, "ebpf_guard_proc_table_events_total"); err != nil || n == 0 {
		t.Fatalf("серия событий таблицы: n=%d err=%v", n, err)
	}
	closeFn()
	if lt.HasProcSource() || !ft.closed {
		t.Fatalf("закрытие не вернуло трекер на прежний путь: has=%v closed=%v", lt.HasProcSource(), ft.closed)
	}
}

// Сбой чтения /proc при засеве не мешает включить таблицу: записи ядра пишутся и без засева.
func TestW85_P1_StartProcTable_SeedReadFailureStillActivates(t *testing.T) {
	ft := &fakeProcTable{}
	lt := ptTracker()
	startProcTable(ptConfig(), lt, false, func(internalbpf.ProcTableConfig) (procTableHandle, error) { return ft, nil },
		func() ([]internalbpf.SeedRecord, error) { return nil, errors.New("/proc unreadable") }, nil, nil)()
	// closeFn вызван — состояние active уже было выставлено до него
	if ptState(internalbpf.ProcTableActive) != 1 {
		t.Fatal("засев не должен блокировать включение")
	}
}
