package main

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/procinfo"
	"github.com/zugolO/ebpf-guard/internal/profiler"
)

// procTableHandle — загруженная таблица процессов: источник записей, засев, метрики, закрытие.
type procTableHandle interface {
	procinfo.Source
	internalbpf.ProcTableStats
	Seed(recs []internalbpf.SeedRecord) (seeded, existing, failed int)
	Close() error
}

// procTableOpener загружает таблицу (в проде — internalbpf.OpenProcTable, в тестах — подставной).
type procTableOpener func(internalbpf.ProcTableConfig) (procTableHandle, error)

func openProcTableKernel(c internalbpf.ProcTableConfig) (procTableHandle, error) {
	t, err := internalbpf.OpenProcTable(c)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// startProcTable включает таблицу процессов ядра (волна 8.5, P1) и подключает её к трекеру
// родословной. Любой отказ оставляет трекер на прежнем пути (Go-карты и /proc) — причина в
// ebpf_guard_proc_table_state и в журнале. Порядок: хуки → засев процессов, существовавших до
// привязки → переключение трекера (иначе в окне между ними цепочки старых демонов были бы пусты).
// Возвращает функцию закрытия (может быть no-op).
func startProcTable(cfg *config.Config, lt *profiler.LineageTracker, dryRun bool, open procTableOpener,
	readSeed func() ([]internalbpf.SeedRecord, error), images *procinfo.ImageCache, reg prometheus.Registerer) func() {

	noop := func() {}
	switch {
	case dryRun:
		internalbpf.SetProcTableState(internalbpf.ProcTableOffDryRun)
		return noop
	case !cfg.BPF.ProcTable.Enabled:
		internalbpf.SetProcTableState(internalbpf.ProcTableOffConfig)
		return noop
	case lt == nil || !lt.Enabled():
		internalbpf.SetProcTableState(internalbpf.ProcTableOffNoLineage)
		return noop
	}
	t, err := open(internalbpf.ProcTableConfig{
		LiveEntries:   uint32(cfg.BPF.ProcTable.LiveEntries),
		ExitedEntries: uint32(cfg.BPF.ProcTable.ExitedEntries),
		TTL:           time.Duration(cfg.Profiler.Lineage.TTL) * time.Second,
		Logger:        slog.Default(),
	})
	if err != nil {
		internalbpf.SetProcTableState(internalbpf.ProcTableOffLoadFailed)
		slog.Warn("proc table: not available, the lineage tracker stays on Go maps and /proc",
			slog.Any("error", err))
		return noop
	}
	if recs, rerr := readSeed(); rerr != nil {
		slog.Warn("proc table: reading /proc for the seed failed — processes older than the agent have no records until they exec",
			slog.Any("error", rerr))
	} else {
		// кэш образов: путь известен из readlink /proc/<pid>/exe, сделанного при чтении засева
		if images != nil {
			for _, r := range recs {
				images.Put(r.ExeDev, r.ExeIno, r.ExePath)
			}
		}
		seeded, existing, failed := t.Seed(recs)
		slog.Info("proc table: seeded with processes older than the agent",
			slog.Int("seeded", seeded), slog.Int("already_recorded_by_kernel", existing), slog.Int("failed", failed))
	}
	if reg != nil {
		if err := internalbpf.RegisterProcTableMetrics(reg, t); err != nil {
			slog.Warn("proc table: failed to register metrics", slog.Any("error", err))
		}
	}
	lt.SetProcSource(t)
	// E1: образ процесса для proc.exe_path — по dev/ino из таблицы, readlink остаётся запасным путём
	correlator.SetExeImageSource(t)
	internalbpf.SetProcTableState(internalbpf.ProcTableActive)
	slog.Info("proc table: active — ancestor chains are read from the kernel, no /proc on the event path",
		slog.Int("live_entries", cfg.BPF.ProcTable.LiveEntries), slog.Int("exited_entries", cfg.BPF.ProcTable.ExitedEntries),
		slog.Duration("ttl", time.Duration(cfg.Profiler.Lineage.TTL)*time.Second))
	return func() {
		correlator.SetExeImageSource(nil)
		lt.SetProcSource(nil)
		_ = t.Close()
	}
}
