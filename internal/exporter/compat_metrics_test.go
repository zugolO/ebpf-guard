package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterCompatMetrics_Empty(t *testing.T) {
	src := prometheus.NewRegistry()
	dst := prometheus.NewRegistry()
	err := RegisterCompatMetrics(CompatMetricsConfig{MetricAliases: nil}, src, dst)
	require.NoError(t, err)
}

func TestRegisterCompatMetrics_FalcoAliases(t *testing.T) {
	// Register the source metric
	src := prometheus.NewRegistry()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_events_total",
		Help: "Total events processed",
	}, []string{"type"})
	src.MustRegister(counter)
	counter.WithLabelValues("syscall").Add(42)

	dst := prometheus.NewRegistry()
	cfg := CompatMetricsConfig{MetricAliases: []string{"falco"}}
	err := RegisterCompatMetrics(cfg, src, dst)
	require.NoError(t, err)

	// Verify alias is registered in dst
	n, err := testutil.GatherAndCount(dst)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "expected falco_events_total to be registered")
}

func TestRegisterCompatMetrics_TetragonAlias(t *testing.T) {
	src := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_events_total",
		Help: "Total events",
	})
	src.MustRegister(g)
	g.Set(100)

	dst := prometheus.NewRegistry()
	err := RegisterCompatMetrics(CompatMetricsConfig{MetricAliases: []string{"tetragon"}}, src, dst)
	require.NoError(t, err)

	n, err := testutil.GatherAndCount(dst)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestRegisterCompatMetrics_UnknownAlias(t *testing.T) {
	src := prometheus.NewRegistry()
	dst := prometheus.NewRegistry()
	// Unknown alias sets are silently ignored
	err := RegisterCompatMetrics(CompatMetricsConfig{MetricAliases: []string{"unknown"}}, src, dst)
	require.NoError(t, err)
}

func TestRegisterCompatMetrics_Idempotent(t *testing.T) {
	src := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_events_total",
		Help: "Total events",
	})
	src.MustRegister(counter)
	counter.Add(1)

	dst := prometheus.NewRegistry()
	cfg := CompatMetricsConfig{MetricAliases: []string{"falco"}}

	// Register twice — should not error
	require.NoError(t, RegisterCompatMetrics(cfg, src, dst))
	require.NoError(t, RegisterCompatMetrics(cfg, src, dst))
}

func TestBuildAliasMap(t *testing.T) {
	m := buildAliasMap([]string{"falco"})
	assert.Equal(t, "falco_events_total", m["ebpf_guard_events_total"])
	assert.Equal(t, "falco_dropped_events_total", m["ebpf_guard_events_dropped_total"])

	m2 := buildAliasMap([]string{"tetragon"})
	assert.Equal(t, "tetragon_events_total", m2["ebpf_guard_events_total"])

	// Multiple sets merged
	m3 := buildAliasMap([]string{"falco", "tetragon"})
	assert.Contains(t, m3, "ebpf_guard_events_total")
	assert.Contains(t, m3, "ebpf_guard_events_dropped_total")
}

func TestForwardingAlias_CounterValue(t *testing.T) {
	src := prometheus.NewRegistry()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_events_total",
		Help: "Total events",
	}, []string{"type"})
	src.MustRegister(counter)
	counter.WithLabelValues("syscall").Add(99)

	alias := newForwardingAlias("falco_events_total", "Falco alias", src, "ebpf_guard_events_total")

	dst := prometheus.NewRegistry()
	dst.MustRegister(alias)

	mfs, err := dst.Gather()
	require.NoError(t, err)
	require.Len(t, mfs, 1)
	assert.Equal(t, "falco_events_total", mfs[0].GetName())
	require.Len(t, mfs[0].GetMetric(), 1)
	assert.InDelta(t, 99.0, mfs[0].GetMetric()[0].GetCounter().GetValue(), 0.001)
}
