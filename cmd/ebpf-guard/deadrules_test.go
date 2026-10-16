package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestUnproducedTypesFromConfig(t *testing.T) {
	cfg := &config.Config{}
	got := unproducedTypesFromConfig(cfg, false)
	require.Contains(t, got, types.EventCloudAudit)
	require.Contains(t, got, types.EventIOUring)
	require.Contains(t, got, types.EventHTTPPlaintext)

	// Любой из трёх облачных коллекторов оживляет cloud_audit.
	cfg.Collectors.AzureMonitor.Enabled = true
	cfg.Collectors.IOUring.Enabled = true
	cfg.Collectors.HTTPPlaintext.Enabled = true
	require.Empty(t, unproducedTypesFromConfig(cfg, false))

	// --dry-run: события этих типов даёт SyntheticCollector.
	require.Empty(t, unproducedTypesFromConfig(&config.Config{}, true))
}

// Д19: на поставляемом наборе и конфиге стенда (всё выключено, фильтр ядра с
// набором по умолчанию) агент называет 57 правил; метрика и API согласованы.
func TestReportDeadRulesShippedSet(t *testing.T) {
	rules, err := correlator.LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	cfg := &config.Config{}
	rep := reportDeadRules(rules, cfg, internalbpf.DefaultMonitoredSyscalls(), false)
	require.Len(t, rep.Dead, 57)
	require.Equal(t, 51, rep.ByAxis[correlator.DeadAxisEventType])
	require.Equal(t, float64(rep.Loaded), testutil.ToFloat64(exporter.RulesLoadedGauge))
	require.Equal(t, float64(rep.Live), testutil.ToFloat64(exporter.RulesLiveGauge))
	require.Equal(t, float64(51), testutil.ToFloat64(exporter.RulesUnreachableByAxis.WithLabelValues("event_type")))
	require.Equal(t, float64(1), testutil.ToFloat64(exporter.RuleUnreachable.WithLabelValues("container_escape_cgroup_migrate", "event_type", "cgroup_esc")))
	require.Len(t, currentDeadRules(), 57)

	// Перезагрузка с включённым облаком пересоздаёт серии (34 правила оживают).
	cfg.Collectors.GCPAudit.Enabled = true
	rep2 := reportDeadRules(rules, cfg, internalbpf.DefaultMonitoredSyscalls(), false)
	require.Len(t, rep2.Dead, 57-34)
	require.Len(t, currentDeadRules(), 57-34)
	require.Equal(t, float64(rep2.Live), testutil.ToFloat64(exporter.RulesLiveGauge))
}
