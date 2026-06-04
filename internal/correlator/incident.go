package correlator

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// incidentRetentionMultiplier controls how long closed incidents remain
// visible after their last alert: retention = window * multiplier.
const incidentRetentionMultiplier = 5

// incidentKey is the grouping key: same PID inside the same Kubernetes
// namespace. Empty namespace covers bare-metal workloads.
type incidentKey struct {
	pid       uint32
	namespace string
}

// IncidentTracker groups consecutive alerts from the same process/namespace
// into Incident records using a sliding time window.
//
// The tracker is embedded in CorrelationEngine and its periodic Cleanup is
// driven by the engine's existing maintenance goroutine — no extra goroutine
// is required.
type IncidentTracker struct {
	window time.Duration

	mu   sync.RWMutex
	open map[incidentKey]*types.Incident // active incidents (last alert within window)
	byID map[string]*types.Incident      // all incidents for ID-based lookups
	seq  atomic.Uint64
}

// newIncidentTracker creates an IncidentTracker with the given sliding window.
// A zero or negative window defaults to 60 seconds.
func newIncidentTracker(window time.Duration) *IncidentTracker {
	if window <= 0 {
		window = 60 * time.Second
	}
	return &IncidentTracker{
		window: window,
		open:   make(map[incidentKey]*types.Incident),
		byID:   make(map[string]*types.Incident),
	}
}

// Add associates alert with the appropriate incident.
// A new incident is created when no open incident exists for (pid, namespace)
// or the most recent alert in the open incident arrived more than window ago.
func (t *IncidentTracker) Add(alert types.Alert) {
	key := incidentKey{pid: alert.PID, namespace: alert.Enrichment.Namespace}
	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	inc, exists := t.open[key]
	if !exists || ts.Sub(inc.LastSeen) > t.window {
		id := t.nextID(ts)
		inc = &types.Incident{
			ID:        id,
			FirstSeen: ts,
			PID:       alert.PID,
			Namespace: alert.Enrichment.Namespace,
			AlertIDs:  make([]string, 0, 4),
			RuleIDs:   make([]string, 0, 4),
		}
		t.open[key] = inc
		t.byID[id] = inc
	}

	inc.LastSeen = ts
	inc.AlertIDs = append(inc.AlertIDs, alert.ID)
	inc.AlertCount = len(inc.AlertIDs)
	inc.Severity = maxIncidentSeverity(inc.Severity, alert.Severity)

	// Append ruleID only if not already present (linear scan is fine for short lists).
	ruleNew := true
	for _, r := range inc.RuleIDs {
		if r == alert.RuleID {
			ruleNew = false
			break
		}
	}
	if ruleNew {
		inc.RuleIDs = append(inc.RuleIDs, alert.RuleID)
	}
}

// GetAll returns a snapshot of all known incidents, applying optional filters.
//   - namespace: if non-empty, only incidents from that namespace are returned.
//   - status: "open", "closed", or "" for both.
//   - limit: maximum number of results; ≤0 returns all matches.
func (t *IncidentTracker) GetAll(namespace, status string, limit int) []types.Incident {
	now := time.Now()
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]types.Incident, 0, len(t.byID))
	for _, inc := range t.byID {
		s := incStatus(inc, now, t.window)
		if namespace != "" && inc.Namespace != namespace {
			continue
		}
		if status != "" && s != status {
			continue
		}
		snap := *inc
		snap.Status = s
		out = append(out, snap)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// GetByID returns a copy of the incident with id, or (nil, false) if unknown.
func (t *IncidentTracker) GetByID(id string) (*types.Incident, bool) {
	now := time.Now()
	t.mu.RLock()
	defer t.mu.RUnlock()

	inc, ok := t.byID[id]
	if !ok {
		return nil, false
	}
	snap := *inc
	snap.Status = incStatus(inc, now, t.window)
	return &snap, true
}

// Cleanup evicts stale entries. Should be called periodically by the caller
// (e.g. the engine's maintenance goroutine).
//
// An open entry is moved to closed (removed from the open map) once its last
// alert is older than window. Entries in byID are evicted once older than
// window * incidentRetentionMultiplier to bound memory growth.
func (t *IncidentTracker) Cleanup(now time.Time) {
	retention := t.window * incidentRetentionMultiplier

	t.mu.Lock()
	defer t.mu.Unlock()

	for k, inc := range t.open {
		if now.Sub(inc.LastSeen) > t.window {
			delete(t.open, k)
		}
	}
	for id, inc := range t.byID {
		if now.Sub(inc.LastSeen) > retention {
			delete(t.byID, id)
		}
	}
}

// Count returns the total number of tracked incidents (open + recently closed).
func (t *IncidentTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byID)
}

// nextID generates a time-sortable, unique incident ID.
// Caller must hold the write lock.
func (t *IncidentTracker) nextID(ts time.Time) string {
	return fmt.Sprintf("inc-%d-%d", ts.UnixMilli(), t.seq.Add(1))
}

// incStatus computes the current status of an incident at read time.
func incStatus(inc *types.Incident, now time.Time, window time.Duration) string {
	if now.Sub(inc.LastSeen) <= window {
		return "open"
	}
	return "closed"
}

// maxIncidentSeverity returns the higher-ranked of two Severity values.
func maxIncidentSeverity(a, b types.Severity) types.Severity {
	if incidentSeverityRank(a) >= incidentSeverityRank(b) {
		return a
	}
	return b
}

func incidentSeverityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 2
	case types.SeverityWarning:
		return 1
	default:
		return 0
	}
}
