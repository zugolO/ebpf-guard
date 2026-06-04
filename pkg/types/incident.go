package types

import "time"

// Incident groups alerts from the same process/namespace that arrive within a
// sliding time window. Incidents give operators a higher-level view of attack
// chains rather than individual per-rule alerts.
type Incident struct {
	ID         string    `json:"id"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	PID        uint32    `json:"pid"`
	Namespace  string    `json:"namespace"`
	AlertIDs   []string  `json:"alert_ids"`
	AlertCount int       `json:"alert_count"`
	Severity   Severity  `json:"severity"`  // maximum severity across grouped alerts
	Status     string    `json:"status"`    // "open" | "closed"
	RuleIDs    []string  `json:"rule_ids"`  // distinct rule IDs contributing to this incident
}
