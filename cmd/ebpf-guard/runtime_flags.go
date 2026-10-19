package main

import (
	"runtime"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/internal/profstage"
)

// publishRuntimeFlags выставляет серии рантайма (волна 8.6, заход C): что на самом деле включено в
// процессе, а не что просили в конфиге. Вызывается ПОСЛЕ включения меток pprof и дампа событий.
func publishRuntimeFlags(cfg *config.Config) {
	evLabels, ruleLabels := correlator.ProfileLabelsState()
	exporter.SetRuntimeFlag("event_dump", correlator.EventDumpActive())
	exporter.SetRuntimeFlag("pprof_event_labels", evLabels)
	exporter.SetRuntimeFlag("pprof_rule_labels", ruleLabels)
	exporter.SetRuntimeFlag("pprof_stage_labels", profstage.Enabled())
	exporter.SetRuntimeFlag("enable_pprof", cfg.Server.EnablePprof)
	exporter.SetRuntimeFlag("pprof_block_mutex", pprofBlockMutexOn())
	// Д15/Д4b (волна 9): что реально работает в процессе, а не что в конфиге.
	exporter.SetRuntimeFlag("rego_built", policy.Supported)
	exporter.SetRuntimeFlag("rego_config", cfg.Policy.Rego.Enabled)
	// Слой реально оценивает политики только при обоих условиях: сборка full и ключ.
	exporter.SetRuntimeFlag("rego_active", policy.Supported && cfg.Policy.Rego.Enabled)
	exporter.SetRuntimeFlag("sequence_profiler", cfg.Profiler.Enabled && cfg.Profiler.Sequence.Enabled)
	exporter.SetRuntimeFlag("arg_predicates_config", cfg.BPF.KernelFilter.ArgPredicates.Enabled)
	iv := cfg.BPF.KernelFilter.ArgPredicates.CountersInterval
	if iv <= 0 {
		iv = defaultKernelPredPeriod // как в runCounters
	}
	exporter.RuntimeCountersInterval.Set(float64(iv) / float64(time.Second))
	exporter.RuntimeBlockBackend.WithLabelValues(cfg.Enforcement.BlockBackend).Set(1)
}

// Волна 8.7, П0(б): профили block и mutex под рантайм-флагом (выключены всегда,
// кроме отдельного окна 10 мин после idle). Ставка 10 мкс блокировки и доля 100
// по мьютексу — шумно, но дёшево; вердикт по CPU на этом окне не берётся.
const (
	blockProfileRateNs = 10_000
	mutexProfileFrac   = 100
)

var blockMutexOn atomic.Bool

func pprofBlockMutexOn() bool { return blockMutexOn.Load() }

func setPprofBlockMutex(on bool) {
	if on {
		runtime.SetBlockProfileRate(blockProfileRateNs)
		runtime.SetMutexProfileFraction(mutexProfileFrac)
	} else {
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
	}
	blockMutexOn.Store(on)
	exporter.SetRuntimeFlag("pprof_block_mutex", on)
}
