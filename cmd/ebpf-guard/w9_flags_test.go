package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/policy"
)

func flag(name string) float64 { return testutil.ToFloat64(exporter.RuntimeFlag.WithLabelValues(name)) }

// 9.1 / Д15, Д4b (волна 9): серии рантайма называют, что реально работает, а не что в конфиге.
// rego_active = сборка full И ключ; sequence_profiler = профайлер включён И sequence.enabled.
func TestW9_RuntimeFlagsRegoAndSequence(t *testing.T) {
	built := 0.0
	if policy.Supported {
		built = 1
	}

	cfg := &config.Config{} // core по умолчанию: Rego и Sequence выключены
	publishRuntimeFlags(cfg)
	require.Equal(t, built, flag("rego_built"), "rego_built следует за тегом сборки")
	require.Equal(t, 0.0, flag("rego_config"))
	require.Equal(t, 0.0, flag("rego_active"), "Rego выключен ключом — слой не работает ни в каком бинаре")
	require.Equal(t, 0.0, flag("sequence_profiler"))

	cfg.Policy.Rego.Enabled = true
	publishRuntimeFlags(cfg)
	require.Equal(t, 1.0, flag("rego_config"))
	require.Equal(t, built, flag("rego_active"), "ключ без тега сборки слой не включает (core + policy.rego.enabled: true)")

	cfg.Profiler.Sequence.Enabled = true
	publishRuntimeFlags(cfg)
	require.Equal(t, 0.0, flag("sequence_profiler"), "sequence.enabled без включённого профайлера не работает")
	cfg.Profiler.Enabled = true
	publishRuntimeFlags(cfg)
	require.Equal(t, 1.0, flag("sequence_profiler"))
	cfg.Profiler.Sequence.Enabled = false
	publishRuntimeFlags(cfg)
	require.Equal(t, 0.0, flag("sequence_profiler"))
}
