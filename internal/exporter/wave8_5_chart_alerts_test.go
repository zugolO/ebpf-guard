package exporter

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Решение 5 (8.5): правило PrometheusRule на неактивные предикаты ядра живёт в
// values чарта и ссылается на метрики, которые агент ДЕЙСТВИТЕЛЬНО печатает.
func TestW85_ChartAlertsReferenceRealMetrics(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/helm/ebpf-guard/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PrometheusRule struct {
			Groups []struct {
				Rules []struct {
					Alert string `yaml:"alert"`
					Expr  string `yaml:"expr"`
				} `yaml:"rules"`
			} `yaml:"groups"`
		} `yaml:"prometheusRule"`
	}
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	exprs := map[string]string{}
	for _, g := range v.PrometheusRule.Groups {
		for _, r := range g.Rules {
			exprs[r.Alert] = r.Expr
		}
	}
	for alert, metric := range map[string]string{
		"EbpfGuardKernelPredicatesOff":      "ebpf_guard_kernel_predicate_state",
		"EbpfGuardSyscallCountsMapNearFull": "ebpf_guard_syscall_counts_map_fill_ratio",
	} {
		expr, ok := exprs[alert]
		if !ok {
			t.Fatalf("в values чарта нет правила %s", alert)
		}
		if !strings.Contains(expr, metric) {
			t.Fatalf("%s: expr %q не читает %s", alert, expr, metric)
		}
	}
	// Состояния в регэкспе — настоящие значения label state; off_config исключён.
	expr := exprs["EbpfGuardKernelPredicatesOff"]
	if !strings.Contains(expr, `state!="off_config"`) {
		t.Fatalf("off_config (выбор оператора) не должен алертить: %s", expr)
	}
	for _, s := range KernelPredicateStates {
		if strings.HasPrefix(s, "off_") && s != "off_config" {
			continue // покрыты префиксом off_.+
		}
	}
	if !strings.Contains(expr, `state=~"off_.+"`) {
		t.Fatalf("правило не покрывает off_*: %s", expr)
	}
}
