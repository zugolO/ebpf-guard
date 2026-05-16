// Package types defines the canonical event structures shared across ebpf-guard components.
package types

import "time"

// EventType identifies the category of a kernel event.
type EventType uint32

const (
	// EventSyscall indicates a syscall tracepoint event.
	EventSyscall EventType = 1
	// EventTCPConnect indicates a TCP connection event.
	EventTCPConnect EventType = 2
	// EventFileAccess indicates a file open/read/write event.
	EventFileAccess EventType = 3
)

// Event is the unified structure for all kernel events.
// Only one of Syscall, Network, or File is populated based on Type.
type Event struct {
	Type      EventType
	Timestamp uint64 // nanoseconds, monotonic
	PID       uint32
	TGID      uint32
	UID       uint32
	Comm      [16]byte // process name from BPF
	// Type-specific fields below (union-style, only one populated)
	Syscall *SyscallEvent
	Network *NetworkEvent
	File    *FileEvent
	// TraceContext holds OpenTelemetry trace context for distributed tracing.
	TraceContext *TraceContext
	// Enrichment holds Kubernetes metadata for the event.
	Enrichment *EnrichmentInfo
}

// EnrichmentInfo contains Kubernetes metadata attached to events/alerts.
type EnrichmentInfo struct {
	PodName     string            `json:"pod_name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	PodUID      string            `json:"pod_uid,omitempty"`
	NodeName    string            `json:"node_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
}

// SyscallEvent contains syscall tracepoint data.
type SyscallEvent struct {
	Nr   int64  // syscall number
	Ret  int64  // return value (from sys_exit)
	Args [6]uint64
}

// AddressFamily indicates the network address family (IPv4 or IPv6).
type AddressFamily uint8

const (
	// AFInet indicates IPv4 address family.
	AFInet AddressFamily = 2
	// AFInet6 indicates IPv6 address family.
	AFInet6 AddressFamily = 10
)

// NetworkEvent contains TCP connection data for IPv4 and IPv6.
type NetworkEvent struct {
	Saddr  [16]byte      // source IP (IPv4 in first 4 bytes, IPv6 uses full 16)
	Daddr  [16]byte      // destination IP (IPv4 in first 4 bytes, IPv6 uses full 16)
	Sport  uint16
	Dport  uint16
	Proto  uint8
	Family AddressFamily // 2=AF_INET, 10=AF_INET6
}

// FileEvent contains file access data.
type FileEvent struct {
	Filename [256]byte
	Flags    int32 // open(2) flags
	Mode     uint32
	Op       uint8 // 0=open, 1=read, 2=write
}

// Severity indicates the severity of a security alert.
type Severity string

const (
	// SeverityWarning indicates a suspicious but not critical event.
	SeverityWarning Severity = "warning"
	// SeverityCritical indicates a high-priority security event.
	SeverityCritical Severity = "critical"
)

// AlertSeverity is an alias for backward compatibility.
type AlertSeverity = Severity

// Alert represents a detected security anomaly or rule violation.
type Alert struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	RuleID     string                 `json:"rule_id"`
	RuleName   string                 `json:"rule_name,omitempty"`
	Severity   Severity               `json:"severity"`
	PID        uint32                 `json:"pid"`
	Comm       string                 `json:"comm"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	TraceID    string                 `json:"trace_id,omitempty"`
	Enrichment EnrichmentInfo         `json:"enrichment,omitempty"`
	Event      Event                  `json:"-"` // the triggering event (not serialized to store)
	// Fingerprint is a SHA-256 hash for tamper detection (optional)
	Fingerprint string `json:"fingerprint,omitempty"`
}

// TraceContext holds OpenTelemetry trace context for propagation.
type TraceContext struct {
	TraceID string
	SpanID  string
}

// AlertPayload is the JSON structure sent to Alertmanager.
type AlertPayload struct {
	Labels       AlertLabels      `json:"labels"`
	Annotations  AlertAnnotations `json:"annotations"`
	GeneratorURL string           `json:"generatorURL"`
}

// AlertLabels contains the identifying labels for an alert.
type AlertLabels struct {
	Alertname   string            `json:"alertname"`
	RuleID      string            `json:"rule_id"`
	Severity    string            `json:"severity"`
	Pod         string            `json:"pod,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	PodLabels   map[string]string `json:"pod_labels,omitempty"`
}

// AlertAnnotations contains human-readable alert metadata.
type AlertAnnotations struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
}

// ProcessProfile represents a learned behavioral profile for a process type.
type ProcessProfile struct {
	Comm           string                 `json:"comm"`
	Namespace      string                 `json:"namespace,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	SyscallCounts  map[int]float64        `json:"syscall_counts"`
	FileAccess     map[string]float64     `json:"file_access"`
	NetworkPeers   map[string]float64     `json:"network_peers"`
	AnomalyScore   float64                `json:"anomaly_score"`
	SampleCount    int64                  `json:"sample_count"`
	Contributions  map[string]float64     `json:"contributions,omitempty"`
}
