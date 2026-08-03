package types

import "time"

type IncidentVerdict string

const (
	VerdictSuspicious IncidentVerdict = "suspicious"
	VerdictAttack     IncidentVerdict = "attack"
)

// Incident groups alerts from the same process/namespace that arrive within a
// sliding time window. Incidents give operators a higher-level view of attack
// chains rather than individual per-rule alerts.
type Incident struct {
	ID           string          `json:"id"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	PID          uint32          `json:"pid"`
	Namespace    string          `json:"namespace"`
	AlertIDs     []string        `json:"alert_ids"`
	AlertCount   int             `json:"alert_count"`
	Severity     Severity        `json:"severity"`                // maximum severity across grouped alerts
	Status       string          `json:"status"`                  // "open" | "closed"
	RuleIDs      []string        `json:"rule_ids"`                // distinct rule IDs contributing to this incident
	RootPID      uint32          `json:"root_pid,omitempty"`      // root ancestor PID from process tree
	ProcessChain []string        `json:"process_chain,omitempty"` // ordered list of process names in the chain
	Verdict      IncidentVerdict `json:"verdict,omitempty"`       // "suspicious" | "attack" based on scoring
	Score        float64         `json:"score,omitempty"`         // incident score (0-100+)
	Tactics      []string        `json:"tactics,omitempty"`       // distinct MITRE tactics represented by the incident's rules

	// CountedAttack / CountedSuspicious latch whether this incident has already
	// been counted in the ebpf_guard_incidents_total metric for the given
	// verdict, so a score oscillating around the threshold cannot inflate the
	// counter. Internal bookkeeping — not part of the API surface.
	CountedAttack     bool `json:"-"`
	CountedSuspicious bool `json:"-"`
}
