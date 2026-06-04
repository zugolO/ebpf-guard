// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ReplayResult holds the outcome of a replay run.
type ReplayResult struct {
	// TotalEvents is the total number of events replayed.
	TotalEvents int
	// MatchedAlerts is the total number of alerts that would have fired.
	MatchedAlerts int
	// AlertsByRule maps rule ID → alert count.
	AlertsByRule map[string]int
	// RuleNames maps rule ID → human-readable name.
	RuleNames map[string]string
	// SampleAlerts holds up to SampleLimit representative alerts for inspection.
	SampleAlerts []types.Alert
	// SampleLimit is the maximum number of sample alerts stored (default 20).
	SampleLimit int
	// Window is the time window that was replayed.
	Window time.Duration
	// EventLogPath is the event log file that was read.
	EventLogPath string
}

// ruleHit is used for sorting the summary output.
type ruleHit struct {
	id    string
	name  string
	count int
}

// PrintSummary writes a human-readable replay report to the returned string.
func (r *ReplayResult) PrintSummary() string {
	if r.TotalEvents == 0 {
		return fmt.Sprintf(
			"No events found in log for the last %s.\n"+
				"Make sure event_log.enabled=true is set in your config and the agent has been running.\n"+
				"Log path checked: %s\n",
			r.Window, r.EventLogPath,
		)
	}

	var hits []ruleHit
	for id, count := range r.AlertsByRule {
		hits = append(hits, ruleHit{id: id, name: r.RuleNames[id], count: count})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].count > hits[j].count })

	out := fmt.Sprintf("Replayed %d events from the last %s\n", r.TotalEvents, r.Window)
	out += fmt.Sprintf("Total alerts that would fire: %d\n", r.MatchedAlerts)

	if len(hits) > 0 {
		out += "\nAlerts by rule (descending):\n"
		out += fmt.Sprintf("  %-12s  %-40s  %s\n", "RULE ID", "NAME", "COUNT")
		out += "  " + repeatDash(68) + "\n"
		for _, h := range hits {
			name := h.name
			if name == "" {
				name = h.id
			}
			out += fmt.Sprintf("  %-12s  %-40s  %d\n", h.id, truncate(name, 40), h.count)
		}
	}

	if len(r.SampleAlerts) > 0 {
		out += fmt.Sprintf("\nFirst %d sample alerts:\n", len(r.SampleAlerts))
		for i, a := range r.SampleAlerts {
			out += fmt.Sprintf("  [%2d] rule=%-20s  sev=%-8s  pid=%-6d  comm=%s\n",
				i+1, a.RuleID, a.Severity, a.PID, a.Comm)
		}
	}
	return out
}

// Replay runs events through the rule engine and collects statistics.
// No side effects: rate limits, enforcement, and anomaly detection are skipped.
func Replay(ctx context.Context, engine *RuleEngine, events []types.Event, window time.Duration, logPath string, sampleLimit int) *ReplayResult {
	if sampleLimit == 0 {
		sampleLimit = 20
	}
	result := &ReplayResult{
		TotalEvents:  len(events),
		AlertsByRule: make(map[string]int),
		RuleNames:    make(map[string]string),
		SampleLimit:  sampleLimit,
		Window:       window,
		EventLogPath: logPath,
	}

	engine.mu.RLock()
	for _, r := range engine.rules {
		result.RuleNames[r.ID] = r.Name
	}
	engine.mu.RUnlock()

	for _, e := range events {
		if ctx.Err() != nil {
			break
		}
		for _, a := range engine.Evaluate(e) {
			result.MatchedAlerts++
			result.AlertsByRule[a.RuleID]++
			if len(result.SampleAlerts) < sampleLimit {
				result.SampleAlerts = append(result.SampleAlerts, a)
			}
		}
	}
	return result
}

func repeatDash(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
