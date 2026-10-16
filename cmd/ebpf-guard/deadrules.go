package main

import (
	"log/slog"
	"sort"
	"sync"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.7, Д19 (№565): единая печать правил, которые в этом запуске не могут
// сработать — на старте и после каждой горячей перезагрузки, в логе, в метрике
// и в GET /rules (поле live).

// unproducedTypesFromConfig — типы событий, у которых по конфигу нет продюсера.
// Тип без продюсера в сборке (cgroup_esc, gpu) движок добавляет сам. В режиме
// --dry-run события этих типов даёт SyntheticCollector.
func unproducedTypesFromConfig(cfg *config.Config, dryRun bool) map[types.EventType]string {
	out := map[types.EventType]string{}
	if dryRun {
		return out
	}
	c := cfg.Collectors
	if !c.CloudTrail.Enabled && !c.GCPAudit.Enabled && !c.AzureMonitor.Enabled {
		out[types.EventCloudAudit] = "no cloud audit collector is enabled (collectors.cloudtrail, collectors.gcp_audit, collectors.azure_monitor are all off), so no event_type cloud_audit event is produced"
	}
	if !c.IOUring.Enabled {
		out[types.EventIOUring] = "collectors.iouring.enabled is false, so no event_type io_uring event is produced"
	}
	if !c.HTTPPlaintext.Enabled {
		out[types.EventHTTPPlaintext] = "collectors.http_plaintext.enabled is false, so no event_type http_plaintext event is produced"
	}
	return out
}

var (
	deadRulesMu   sync.RWMutex
	deadRulesAxis = map[string]string{}
)

// currentDeadRules — правило → ось (для GET /rules).
func currentDeadRules() map[string]string {
	deadRulesMu.RLock()
	defer deadRulesMu.RUnlock()
	return deadRulesAxis
}

// reportDeadRules считает мёртвые правила набора, печатает итог (и по типу
// события — причину), выставляет метрики и список для API. nrAllowlist == nil —
// ось nr не проверяется (фильтр ядра выключен).
func reportDeadRules(rules []correlator.Rule, cfg *config.Config, nrAllowlist []int, dryRun bool) correlator.DeadRulesReport {
	rep := correlator.NewRuleEngine(rules).DeadRules(nrAllowlist, unproducedTypesFromConfig(cfg, dryRun))

	series := make([]exporter.DeadRuleSeries, 0, len(rep.Dead))
	axis := make(map[string]string, len(rep.Dead))
	byType := map[string][]string{}
	reasons := map[string]string{}
	for _, d := range rep.Dead {
		series = append(series, exporter.DeadRuleSeries{RuleID: d.RuleID, Axis: d.Axis, EventType: d.EventType})
		axis[d.RuleID] = d.Axis
		if d.Axis == correlator.DeadAxisEventType {
			byType[d.EventType] = append(byType[d.EventType], d.RuleID)
			reasons[d.EventType] = d.Reason
		}
	}
	exporter.SetDeadRules(rep.Loaded, rep.Live, series)
	deadRulesMu.Lock()
	deadRulesAxis = axis
	deadRulesMu.Unlock()

	ets := make([]string, 0, len(byType))
	for et := range byType {
		ets = append(ets, et)
	}
	sort.Strings(ets)
	for _, et := range ets {
		ids := byType[et]
		slog.Warn("rules: rules standing on an event type nothing produces in this run",
			slog.String("event_type", et), slog.Int("count", len(ids)),
			slog.Any("rule_ids", ids), slog.String("reason", reasons[et]))
	}
	slog.Warn("rules: coverage counts live rules only",
		slog.Int("loaded", rep.Loaded), slog.Int("live", rep.Live), slog.Int("unreachable", len(rep.Dead)),
		slog.Any("by_axis", rep.ByAxis))
	return rep
}
