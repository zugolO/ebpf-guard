// Package exporter provides Prometheus metric aliases for migration compatibility.
package exporter

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// CompatMetricsConfig holds configuration for metric aliases.
type CompatMetricsConfig struct {
	// MetricAliases is the list of alias sets to enable: "falco", "tetragon", "kubearmor"
	MetricAliases []string
}

// falcoAliasMap maps ebpf-guard metric names to Falco metric names.
var falcoAliasMap = map[string]string{
	"ebpf_guard_events_total":         "falco_events_total",
	"ebpf_guard_events_dropped_total": "falco_dropped_events_total",
}

// tetragonAliasMap maps ebpf-guard metric names to Tetragon metric names.
var tetragonAliasMap = map[string]string{
	"ebpf_guard_events_total": "tetragon_events_total",
}

// kubeArmorAliasMap maps ebpf-guard metric names to KubeArmor metric names.
var kubeArmorAliasMap = map[string]string{
	"ebpf_guard_events_total": "kubearmor_events_total",
}

// MetricAlias wraps an existing prometheus.Collector and re-registers it
// under an alias name. The alias collector delegates all Describe/Collect
// calls to the underlying collector, so no data is duplicated.
type MetricAlias struct {
	aliasName   string
	aliasHelp   string
	wrapped     prometheus.Collector
	aliasDesc   *prometheus.Desc
}

// RegisterCompatMetrics registers metric aliases in the given registry.
// It reads the current metric descriptors from the default (source) registry
// and creates alias collectors in the target registry.
func RegisterCompatMetrics(cfg CompatMetricsConfig, sourceGatherer prometheus.Gatherer, targetRegisterer prometheus.Registerer) error {
	if len(cfg.MetricAliases) == 0 {
		return nil
	}

	// Collect the desired alias maps
	aliases := buildAliasMap(cfg.MetricAliases)
	if len(aliases) == 0 {
		return nil
	}

	// Gather current metric families to get help text
	mfs, err := sourceGatherer.Gather()
	if err != nil {
		return fmt.Errorf("compat_metrics: gather source metrics: %w", err)
	}

	helpByName := make(map[string]string, len(mfs))
	for _, mf := range mfs {
		helpByName[mf.GetName()] = mf.GetHelp()
	}

	for srcName, aliasName := range aliases {
		help, ok := helpByName[srcName]
		if !ok {
			// Source metric not yet registered; skip gracefully
			continue
		}

		alias := newForwardingAlias(aliasName, help+"(alias for "+srcName+")", sourceGatherer, srcName)
		if err := targetRegisterer.Register(alias); err != nil {
			// Already registered — not an error in idempotent setups
			if _, dup := err.(prometheus.AlreadyRegisteredError); !dup {
				return fmt.Errorf("compat_metrics: register alias %s: %w", aliasName, err)
			}
		}
	}
	return nil
}

// buildAliasMap merges the requested alias sets into a single src→alias map.
func buildAliasMap(sets []string) map[string]string {
	result := make(map[string]string)
	for _, set := range sets {
		var m map[string]string
		switch set {
		case "falco":
			m = falcoAliasMap
		case "tetragon":
			m = tetragonAliasMap
		case "kubearmor":
			m = kubeArmorAliasMap
		default:
			continue
		}
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// forwardingAlias is a prometheus.Collector that re-exposes metrics from a
// source Gatherer under a different name. It replaces the metric name in each
// MetricFamily but keeps all labels and values identical.
type forwardingAlias struct {
	aliasName string
	aliasHelp string
	gatherer  prometheus.Gatherer
	srcName   string
	descCh    chan *prometheus.Desc
}

func newForwardingAlias(aliasName, aliasHelp string, g prometheus.Gatherer, srcName string) *forwardingAlias {
	return &forwardingAlias{
		aliasName: aliasName,
		aliasHelp: aliasHelp,
		gatherer:  g,
		srcName:   srcName,
	}
}

// Describe sends a synthetic descriptor for the alias metric.
func (f *forwardingAlias) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc(f.aliasName, f.aliasHelp, nil, nil)
}

// Collect re-gathers the source metric and emits it under the alias name.
func (f *forwardingAlias) Collect(ch chan<- prometheus.Metric) {
	mfs, err := f.gatherer.Gather()
	if err != nil {
		return
	}
	for _, mf := range mfs {
		if mf.GetName() != f.srcName {
			continue
		}
		for _, m := range mf.GetMetric() {
			// Build label names and values
			var labelNames []string
			var labelValues []string
			for _, lp := range m.GetLabel() {
				labelNames = append(labelNames, lp.GetName())
				labelValues = append(labelValues, lp.GetValue())
			}

			desc := prometheus.NewDesc(f.aliasName, f.aliasHelp, labelNames, nil)

			var pm prometheus.Metric
			var convErr error

			switch {
			case m.GetCounter() != nil:
				pm, convErr = prometheus.NewConstMetric(desc, prometheus.CounterValue,
					m.GetCounter().GetValue(), labelValues...)
			case m.GetGauge() != nil:
				pm, convErr = prometheus.NewConstMetric(desc, prometheus.GaugeValue,
					m.GetGauge().GetValue(), labelValues...)
			case m.GetUntyped() != nil:
				pm, convErr = prometheus.NewConstMetric(desc, prometheus.UntypedValue,
					m.GetUntyped().GetValue(), labelValues...)
			default:
				// Histograms and summaries are not forwarded (complex wire format)
				continue
			}

			if convErr == nil {
				ch <- pm
			}
		}
	}
}
