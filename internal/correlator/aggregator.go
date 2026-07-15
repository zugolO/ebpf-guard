package correlator

import (
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// AlertAggregationConfig controls alert aggregation: folding repeated alerts
// that share the same (rule_id, comm, normalized path prefix, pod/namespace)
// key within a sliding time window into a single alert object carrying a
// Count and FirstSeen/LastSeen, instead of forwarding one row per occurrence
// to storage and notification backends.
//
// This is distinct from the engine's sliding-window Dedup filter, which drops
// repeats outright and keeps no count. Aggregation always forwards the first
// occurrence of a key immediately (no latency for the real incident) and
// later reports the final count once the window closes.
type AlertAggregationConfig struct {
	// Enabled activates aggregation. Default: false (no behavior change).
	Enabled bool
	// Window is the aggregation period. Repeats of the same key within this
	// window after the first occurrence are folded into one alert. Default: 60s.
	Window time.Duration
}

// DefaultAlertAggregationConfig returns the default aggregation settings
// (disabled, 60s window).
func DefaultAlertAggregationConfig() AlertAggregationConfig {
	return AlertAggregationConfig{Enabled: false, Window: 60 * time.Second}
}

// aggregateEntry tracks the running aggregate for one key within its window.
type aggregateEntry struct {
	alert     types.Alert
	windowEnd time.Time
}

// AlertAggregator folds repeated alerts sharing an aggregation key into a
// single alert with a running count, so an operator sees one incident with
// count=N instead of N separate alert rows. Safe for concurrent use.
type AlertAggregator struct {
	mu      sync.Mutex
	cfg     AlertAggregationConfig
	entries map[string]*aggregateEntry
}

// NewAlertAggregator creates an AlertAggregator with the given configuration.
func NewAlertAggregator(cfg AlertAggregationConfig) *AlertAggregator {
	if cfg.Window <= 0 {
		cfg.Window = 60 * time.Second
	}
	return &AlertAggregator{
		cfg:     cfg,
		entries: make(map[string]*aggregateEntry),
	}
}

// Ingest processes freshly generated alerts and returns only the alerts that
// should be forwarded to storage/notifications immediately: alerts whose
// aggregation key opens a new window. Repeats of a key already inside an open
// window are folded into that key's running count and are not returned here —
// call Reap once the window closes to obtain the final aggregated alert.
//
// Callers must record per-event metrics (e.g. Prometheus alerts_total) against
// the input slice *before* calling Ingest, since aggregation intentionally
// reduces what gets forwarded downstream.
func (a *AlertAggregator) Ingest(alerts []types.Alert, now time.Time) []types.Alert {
	if !a.cfg.Enabled || len(alerts) == 0 {
		return alerts
	}

	var out []types.Alert
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, alert := range alerts {
		key := aggregationKey(alert)
		entry, ok := a.entries[key]
		if !ok || now.After(entry.windowEnd) {
			head := alert
			head.Count = 1
			head.FirstSeen = now
			head.LastSeen = now
			a.entries[key] = &aggregateEntry{alert: head, windowEnd: now.Add(a.cfg.Window)}
			out = append(out, head)
			continue
		}
		entry.alert.Count++
		entry.alert.LastSeen = now
	}
	return out
}

// Reap closes out aggregation windows that have expired as of now and
// returns an updated alert for each key that received at least one repeat
// (Count > 1) since it was first forwarded by Ingest. Keys with no repeats
// are dropped without generating a second alert. Call periodically (e.g.
// every Window/2) and forward the result through the same downstream path
// used for fresh alerts.
func (a *AlertAggregator) Reap(now time.Time) []types.Alert {
	if !a.cfg.Enabled {
		return nil
	}

	var out []types.Alert
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, entry := range a.entries {
		if now.Before(entry.windowEnd) {
			continue
		}
		if entry.alert.Count > 1 {
			out = append(out, entry.alert)
		}
		delete(a.entries, key)
	}
	return out
}

// aggregationKey builds the composite aggregation key: rule_id + comm +
// normalized path prefix + namespace + pod. Distinct keys never collapse
// into one another.
func aggregationKey(alert types.Alert) string {
	var sb strings.Builder
	sb.WriteString(alert.RuleID)
	sb.WriteByte('|')
	sb.WriteString(alert.Comm)
	sb.WriteByte('|')
	sb.WriteString(normalizePathPrefix(alertPath(alert)))
	sb.WriteByte('|')
	sb.WriteString(alert.Enrichment.Namespace)
	sb.WriteByte('|')
	sb.WriteString(alert.Enrichment.PodName)
	return sb.String()
}

// alertPath extracts the file path (when any) from the alert's triggering
// event, preferring the fd-resolved path over the raw filename.
func alertPath(alert types.Alert) string {
	if alert.Event.File != nil {
		if alert.Event.File.FDPath != "" {
			return alert.Event.File.FDPath
		}
		return util.BytesToString(alert.Event.File.Filename[:])
	}
	return ""
}

// pathPrefixMaxDepth bounds how many path segments contribute to the
// aggregation key, so e.g. "/etc/passwd" and "/etc/shadow" collapse to the
// same "/etc" prefix while distinct top-level directories do not.
const pathPrefixMaxDepth = 2

// normalizePathPrefix reduces a file path to a short, PID/inode-independent
// prefix so that repeated writes to different files under the same directory
// (or repeated access to the same file via different numeric identifiers,
// e.g. /proc/<pid>/mem) collapse to one aggregation key.
func normalizePathPrefix(path string) string {
	if path == "" {
		return ""
	}
	segs := strings.Split(path, "/")
	kept := make([]string, 0, pathPrefixMaxDepth)
	for _, s := range segs {
		if s == "" {
			continue
		}
		if isNumeric(s) {
			s = "*"
		}
		kept = append(kept, s)
		if len(kept) >= pathPrefixMaxDepth {
			break
		}
	}
	return "/" + strings.Join(kept, "/")
}

// isNumeric reports whether s consists entirely of ASCII digits (non-empty).
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
