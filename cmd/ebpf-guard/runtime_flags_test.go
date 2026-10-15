package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
)

// Волна 8.6 C: флаги рантайма читаются из процесса, а не из конфига — дамп событий и метки правил
// выключены, pprof включён, интервал счётчиков и бэкенд блокировки названы.
func TestPublishRuntimeFlags(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.EnablePprof = true
	cfg.Enforcement.BlockBackend = "log"
	cfg.BPF.KernelFilter.ArgPredicates.Enabled = true
	cfg.BPF.KernelFilter.ArgPredicates.CountersInterval = 15 * time.Second
	correlator.SetProfileLabels(true, false)
	publishRuntimeFlags(cfg)
	require.Equal(t, 0.0, testutil.ToFloat64(exporter.RuntimeFlag.WithLabelValues("event_dump")))
	require.Equal(t, 1.0, testutil.ToFloat64(exporter.RuntimeFlag.WithLabelValues("pprof_event_labels")))
	require.Equal(t, 0.0, testutil.ToFloat64(exporter.RuntimeFlag.WithLabelValues("pprof_rule_labels")))
	require.Equal(t, 1.0, testutil.ToFloat64(exporter.RuntimeFlag.WithLabelValues("enable_pprof")))
	require.Equal(t, 1.0, testutil.ToFloat64(exporter.RuntimeFlag.WithLabelValues("arg_predicates_config")))
	require.Equal(t, 15.0, testutil.ToFloat64(exporter.RuntimeCountersInterval))
	require.Equal(t, 1.0, testutil.ToFloat64(exporter.RuntimeBlockBackend.WithLabelValues("log")))
	// мутация: меняем рантайм, не конфиг, — серия обязана следовать за процессом
	correlator.SetProfileLabels(true, true)
	publishRuntimeFlags(cfg)
	require.Equal(t, 1.0, testutil.ToFloat64(exporter.RuntimeFlag.WithLabelValues("pprof_rule_labels")))
	correlator.SetProfileLabels(false, false)
}
