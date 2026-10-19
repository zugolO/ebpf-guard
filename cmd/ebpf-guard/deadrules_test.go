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

// Д19 + Д15 (волна 9, В1): на поставляемом наборе и конфиге стенда (всё
// выключено, фильтр ядра с набором по умолчанию) агент называет 11 правил — 34
// cloud_audit, 9 gpu и 3 io_uring вынесены из поставки в rules/optional;
// метрика и API согласованы.
func TestReportDeadRulesShippedSet(t *testing.T) {
	rules, err := correlator.LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	cfg := &config.Config{}
	rep := reportDeadRules(rules, cfg, internalbpf.DefaultMonitoredSyscalls(), false)
	require.Len(t, rep.Dead, 11)
	require.Equal(t, 5, rep.ByAxis[correlator.DeadAxisEventType])
	require.Equal(t, float64(rep.Loaded), testutil.ToFloat64(exporter.RulesLoadedGauge))
	require.Equal(t, float64(rep.Live), testutil.ToFloat64(exporter.RulesLiveGauge))
	require.Equal(t, float64(5), testutil.ToFloat64(exporter.RulesUnreachableByAxis.WithLabelValues("event_type")))
	require.Equal(t, float64(1), testutil.ToFloat64(exporter.RuleUnreachable.WithLabelValues("container_escape_cgroup_migrate", "event_type", "cgroup_esc")))
	require.Len(t, currentDeadRules(), 11)

	// Опциональный набор (rules/optional, вне поставки): без коллектора все 46
	// его правила мертвы по оси event_type, с включённым облаком 34 из них
	// оживают, а перезагрузка пересоздаёт серии.
	optional, err := correlator.LoadRulesFromDir("../../rules/optional")
	require.NoError(t, err)
	require.Len(t, optional, 46)
	all := append(append([]correlator.Rule{}, rules...), optional...)
	repOff := reportDeadRules(all, cfg, internalbpf.DefaultMonitoredSyscalls(), false)
	require.Len(t, repOff.Dead, 11+46)
	cfg.Collectors.GCPAudit.Enabled = true
	rep2 := reportDeadRules(all, cfg, internalbpf.DefaultMonitoredSyscalls(), false)
	require.Len(t, rep2.Dead, 11+46-34)
	require.Equal(t, float64(rep2.Live), testutil.ToFloat64(exporter.RulesLiveGauge))
}
