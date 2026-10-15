package main

import (
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
)

// publishRuntimeFlags выставляет серии рантайма (волна 8.6, заход C): что на самом деле включено в
// процессе, а не что просили в конфиге. Вызывается ПОСЛЕ включения меток pprof и дампа событий.
func publishRuntimeFlags(cfg *config.Config) {
	evLabels, ruleLabels := correlator.ProfileLabelsState()
	exporter.SetRuntimeFlag("event_dump", correlator.EventDumpActive())
	exporter.SetRuntimeFlag("pprof_event_labels", evLabels)
	exporter.SetRuntimeFlag("pprof_rule_labels", ruleLabels)
	exporter.SetRuntimeFlag("enable_pprof", cfg.Server.EnablePprof)
	exporter.SetRuntimeFlag("arg_predicates_config", cfg.BPF.KernelFilter.ArgPredicates.Enabled)
	iv := cfg.BPF.KernelFilter.ArgPredicates.CountersInterval
	if iv <= 0 {
		iv = defaultKernelPredPeriod // как в runCounters
	}
	exporter.RuntimeCountersInterval.Set(float64(iv) / float64(time.Second))
	exporter.RuntimeBlockBackend.WithLabelValues(cfg.Enforcement.BlockBackend).Set(1)
}
