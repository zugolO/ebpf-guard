package types

import "time"

type IncidentVerdict string

const (
	// VerdictNone marks an incident whose alerts never reached scoring — e.g.
	// all-info incidents under 5.5a, which are deliberately kept out of the
	// score entirely. Explicit so an empty JSON verdict is never mistaken for
	// "scoring failed to run" (5.7e, находка №17).
	VerdictNone       IncidentVerdict = "none"
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
	Comm         string          `json:"comm"`                // leaf process name (most recent alert's comm); P1-27
	Namespace    string          `json:"namespace"`
	AlertIDs     []string        `json:"alert_ids"`
	AlertCount   int             `json:"alert_count"`
	Severity     Severity        `json:"severity"`                // maximum severity across grouped alerts
	Status       string          `json:"status"`                  // "open" | "closed"
	RuleIDs      []string        `json:"rule_ids"`                // distinct rule IDs contributing to this incident
	RootPID      uint32          `json:"root_pid,omitempty"`      // root ancestor PID from process tree
	RootComm     string          `json:"root_comm,omitempty"`     // root ancestor comm; P1-27
	ProcessChain []string        `json:"process_chain,omitempty"` // ordered list of process names in the chain
	// ProcessTree is the SAME chain as ProcessChain, but carrying the pid of
	// every hop (wave 6.2.9.F.1, item 5 / №262). ProcessChain records names
	// only, so any trust decision taken while walking it can be taken on a
	// NAME — and a name is spoofable (`exec -a flannel`). The pid-bearing
	// form lets containerInitTrustedRoot verify a plumbing hop by its IMAGE
	// (readlink /proc/<pid>/exe) instead, which is the anti-spoof axis this
	// cluster of waves is built on. Internal bookkeeping: the exported shape
	// of an incident does not change, and consumers keep reading
	// process_chain.
	ProcessTree ProcessTree `json:"-"`
	Comms        []string        `json:"comms,omitempty"`         // distinct process names across grouped alerts (only when >1); P1-27
	Verdict      IncidentVerdict `json:"verdict,omitempty"`       // "suspicious" | "attack" based on scoring
	Score        float64         `json:"score,omitempty"`         // incident score (0-100+)
	Tactics      []string        `json:"tactics,omitempty"`       // distinct MITRE tactics represented by the incident's rules

	// CountedAttack / CountedSuspicious latch whether this incident has already
	// been counted in the ebpf_guard_incidents_total metric for the given
	// verdict, so a score oscillating around the threshold cannot inflate the
	// counter. Internal bookkeeping — not part of the API surface.
	CountedAttack     bool `json:"-"`
	CountedSuspicious bool `json:"-"`

	// SourceEvents counts the distinct (pid, event timestamp) pairs behind this
	// incident's alerts. P1-13: a single kernel event (sshd reading /etc/passwd
	// at login) can trip five rules at once, one source event masquerading as
	// five independent signals. Scoring counts distinct source events, not
	// distinct alerts, so this fan-out cannot manufacture unique-rule score on
	// its own. Internal bookkeeping — not part of the API surface.
	SourceEvents map[uint64]struct{} `json:"-"`
	// ScoringRuleIDs mirrors RuleIDs but excludes rules that only ever fired at
	// info severity. Wave 5.5a: info alerts remain fully visible in RuleIDs,
	// AlertIDs and alerts_filtered_total (пункт 8 — nothing disappears without
	// a record), but the intake filter that keeps them out of alerts_total and
	// the store sits downstream of the correlator, so IncidentTracker still saw
	// the full info stream and let it alone manufacture uniqueRules/tactics
	// score (находка №8, замер №2.1). ScoringRuleIDs and ScoringSourceEvents
	// are the same bookkeeping as RuleIDs/SourceEvents, populated only from
	// warning/critical alerts, so scoring reads a clean input without touching
	// observability. Internal bookkeeping — not part of the API surface.
	ScoringRuleIDs map[string]struct{} `json:"-"`
	// ScoringSourceEvents is SourceEvents restricted to warning/critical
	// alerts — see ScoringRuleIDs.
	ScoringSourceEvents map[uint64]struct{} `json:"-"`
	// ScoringAlertCount is AlertCount restricted to warning/critical alerts,
	// used for the time-density score so an info-only burst cannot inflate
	// density either — see ScoringRuleIDs.
	ScoringAlertCount int `json:"-"`
	// UntrustedComms is the set of distinct comms that have contributed an
	// alert from outside the trusted allowlist (see defaultTrustedComms) to
	// this incident. A set rather than a latched bool (wave 6.2.6, №276): the
	// container-init trust gate (containerInitTrustedRoot) depends on the
	// incident's process chain, which grows across alerts arriving
	// milliseconds apart — a bool decided once, at the comm's own arrival,
	// cannot be revisited once the chain later resolves to a trusted actor.
	// Whether a comm here still qualifies as an untrusted signal is
	// recomputed against the CURRENT chain at every scoring pass — see
	// IncidentTracker.hasQualifyingUntrustedComm.
	UntrustedComms map[string]struct{} `json:"-"`
	// HasNetworkSignal is true once an alert whose triggering event is a
	// network/dns/tls event has contributed to this incident.
	HasNetworkSignal bool `json:"-"`
	// RootUnit is the systemd unit the incident's ROOT process belongs to,
	// resolved once from /proc/<RootPID>/cgroup at the moment the incident is
	// created (wave 6.2.9.F.1, item 4 — criterion 6.2.4.6). Empty when the
	// root has no unit, has already exited, or no resolver is wired: an empty
	// value means "the unit axis does not apply", never "trusted".
	RootUnit string `json:"root_unit,omitempty"`
	// HasHardEvidence is true once an alert that no periodic-task allowlist
	// may excuse has contributed: a rule tagged container-escape / persistence
	// / impact / rootkit, or a process executing out of a world-writable
	// directory. An attack INSIDE a trusted unit stays detectable — only the
	// soft recon/enum/anomaly shape loses its automatic "confirmed attack"
	// label. Internal bookkeeping.
	HasHardEvidence bool `json:"-"`
}
