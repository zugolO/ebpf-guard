// Package types defines the canonical event structures shared across ebpf-guard components.
package types

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EventType identifies the category of a kernel event.
type EventType uint32

const (
	// EventSyscall indicates a syscall tracepoint event.
	EventSyscall EventType = 1
	// EventTCPConnect indicates a TCP connection event.
	EventTCPConnect EventType = 2
	// EventFileAccess indicates a file open/read/write event.
	EventFileAccess EventType = 3
	// EventTLS indicates a TLS plaintext inspection event.
	EventTLS EventType = 4
	// EventDNS indicates a DNS query/response event.
	EventDNS EventType = 5
	// EventPrivesc indicates a privilege escalation event (capability change).
	EventPrivesc EventType = 6
	// EventNetClose indicates a TCP connection-close event with duration.
	EventNetClose EventType = 7
	// EventKmodLoad indicates a kernel module load event.
	EventKmodLoad EventType = 8
	// EventCgroupEsc indicates a process migrating to a different cgroup namespace.
	EventCgroupEsc EventType = 9
	// EventGPU indicates a CUDA/GPU memory operation (alloc, free, DtoH copy, HtoD copy).
	EventGPU EventType = 10
	// EventLSMAudit indicates an LSM hook audit record (file_open block, socket_connect block, task_kill).
	EventLSMAudit EventType = 11
	// EventSequence is a placeholder for multi-event sequence rules (future).
	EventSequence EventType = 12
	// EventCloudAudit indicates a cloud control-plane audit event (AWS CloudTrail, GCP Audit Logs, Azure Activity Log).
	EventCloudAudit EventType = 13
	// EventIOUring indicates an io_uring activity event (setup or enter).
	EventIOUring EventType = 14
	// EventBPFProgram indicates a bpf() syscall event: BPF_PROG_LOAD or BPF_MAP_CREATE.
	EventBPFProgram EventType = 15
)

// eventTypeCanonical maps each EventType to its single canonical lowercase
// name. It is the one source of truth for turning an EventType into a string
// label (metrics, logs, UIs); consumers should call EventType.String() rather
// than hand-maintaining their own switch, so adding a new EventType here makes
// every consumer pick up its label automatically.
var eventTypeCanonical = map[EventType]string{
	EventSyscall:    "syscall",
	EventTCPConnect: "tcp_connect",
	EventFileAccess: "file",
	EventTLS:        "tls",
	EventDNS:        "dns",
	EventPrivesc:    "privesc",
	EventNetClose:   "net_close",
	EventKmodLoad:   "kmod",
	EventCgroupEsc:  "cgroup_esc",
	EventGPU:        "gpu",
	EventLSMAudit:   "lsm_audit",
	EventSequence:   "sequence",
	EventCloudAudit: "cloud_audit",
	EventIOUring:    "io_uring",
	EventBPFProgram: "bpf_program",
}

// String returns the canonical lowercase name of the event type, or "unknown"
// for an unmapped value.
func (et EventType) String() string {
	if s, ok := eventTypeCanonical[et]; ok {
		return s
	}
	return "unknown"
}

// BPFProgType maps numeric BPF program types to human-readable strings.
var bpfProgTypeNames = map[uint32]string{
	0:  "SOCKET_FILTER",
	3:  "SCHED_CLS",
	4:  "SCHED_ACT",
	5:  "TRACEPOINT",
	6:  "XDP",
	8:  "CGROUP_SKB",
	11: "SK_MSG",
	15: "KPROBE",
	17: "CGROUP_SOCK_ADDR",
	26: "LSM",
	28: "STRUCT_OPS",
	31: "SK_LOOKUP",
}

// BPF command numbers for the bpf(2) syscall.
const (
	BPFCmdMapCreate    uint32 = 0
	BPFCmdMapLookup    uint32 = 1
	BPFCmdMapUpdate    uint32 = 2
	BPFCmdMapDelete    uint32 = 3
	BPFCmdMapGetNextKey uint32 = 4
	BPFCmdProgLoad     uint32 = 5
	BPFCmdObjPin       uint32 = 6
	BPFCmdObjGet       uint32 = 7
	BPFCmdProgAttach   uint32 = 8
	BPFCmdProgDetach   uint32 = 9
)

// BPFCmdName returns the human-readable name for a bpf() command number.
func BPFCmdName(cmd uint32) string {
	switch cmd {
	case BPFCmdMapCreate:
		return "MAP_CREATE"
	case BPFCmdMapLookup:
		return "MAP_LOOKUP_ELEM"
	case BPFCmdMapUpdate:
		return "MAP_UPDATE_ELEM"
	case BPFCmdMapDelete:
		return "MAP_DELETE_ELEM"
	case BPFCmdMapGetNextKey:
		return "MAP_GET_NEXT_KEY"
	case BPFCmdProgLoad:
		return "PROG_LOAD"
	case BPFCmdObjPin:
		return "OBJ_PIN"
	case BPFCmdObjGet:
		return "OBJ_GET"
	case BPFCmdProgAttach:
		return "PROG_ATTACH"
	case BPFCmdProgDetach:
		return "PROG_DETACH"
	default:
		return fmt.Sprintf("BPF_CMD_%d", cmd)
	}
}

// BPFProgTypeName returns the human-readable name for a BPF program type.
func BPFProgTypeName(t uint32) string {
	if name, ok := bpfProgTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", t)
}

// eventTypeNames maps string names used in rule YAML to numeric EventType constants.
// Kept lowercase; matching is case-insensitive.
var eventTypeNames = map[string]EventType{
	"syscall":     EventSyscall,
	"network":     EventTCPConnect,
	"tcp_connect": EventTCPConnect,
	"file":        EventFileAccess,
	"file_access": EventFileAccess,
	"tls":         EventTLS,
	"dns":         EventDNS,
	"privesc":     EventPrivesc,
	"net_close":   EventNetClose,
	"kmod":        EventKmodLoad,
	"kmod_load":   EventKmodLoad,
	"cgroup_esc":  EventCgroupEsc,
	"gpu":         EventGPU,
	"lsm_audit":   EventLSMAudit,
	"sequence":    EventSequence,
	"cloud_audit": EventCloudAudit,
	"cloud":       EventCloudAudit,
	"iouring":       EventIOUring,
	"io_uring":      EventIOUring,
	"bpf_program":   EventBPFProgram,
	"bpf_prog_load": EventBPFProgram,
	"bpf":           EventBPFProgram,
}

// UnmarshalYAML allows EventType to be decoded from both numeric and string YAML values.
// Rule files may use either form: `event_type: 3` or `event_type: file`.
func (et *EventType) UnmarshalYAML(value *yaml.Node) error {
	var n uint32
	if err := value.Decode(&n); err == nil {
		*et = EventType(n)
		return nil
	}
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("event_type must be a number or string, got: %s", value.Value)
	}
	mapped, ok := eventTypeNames[strings.ToLower(s)]
	if !ok {
		return fmt.Errorf("unknown event_type %q", s)
	}
	*et = mapped
	return nil
}

// Event is the unified structure for all kernel events.
// Only one of Syscall, Network, File, TLS, DNS, Privesc, or NetClose is populated based on Type.
type Event struct {
	Type       EventType
	Timestamp  uint64 // nanoseconds, monotonic
	PID        uint32
	TGID       uint32
	PPID       uint32 // parent process ID
	UID        uint32
	Comm       [16]byte // process name from BPF
	ParentComm [16]byte // parent process name (if available)
	// Type-specific fields below (union-style, only one populated)
	Syscall    *SyscallEvent
	Network    *NetworkEvent
	File       *FileEvent
	TLS        *TLSEvent
	DNS        *DNSEvent
	Privesc    *PrivescEvent
	NetClose   *NetworkCloseEvent
	Kmod       *KmodEvent
	CgroupEsc  *CgroupEscapeEvent
	GPU        *GPUEvent
	// CloudAudit holds cloud control-plane audit data (AWS CloudTrail, GCP Audit Logs).
	// Populated when Type == EventCloudAudit.
	CloudAudit *CloudAuditEvent
	// IOUring holds io_uring activity data (setup/enter).
	// Populated when Type == EventIOUring.
	IOUring *IOUringEvent
	// BPFProgram holds bpf() syscall monitoring data (BPF_PROG_LOAD / BPF_MAP_CREATE).
	// Populated when Type == EventBPFProgram.
	BPFProgram *BPFProgramEvent
	// LSMAudit holds an LSM-hook audit record (ai_sandbox sandbox_audit/sandbox_deny
	// decisions, plus enforcer file_open / socket_connect / task_kill blocks).
	// Populated when Type == EventLSMAudit.
	LSMAudit *LSMAuditEvent
	// TraceContext holds OpenTelemetry trace context for distributed tracing.
	TraceContext *TraceContext
	// Enrichment holds Kubernetes metadata for the event.
	Enrichment *EnrichmentInfo
	// ProcArgs contains the space-separated command-line arguments for the process,
	// read from /proc/PID/cmdline (fallback) or the BPF proc_args_map (primary path).
	// Available as the "proc.args" rule field for syscall (execve), file, and network events.
	ProcArgs string
	// ProcArgsTruncated is true when the original cmdline exceeded 512 bytes and was truncated.
	ProcArgsTruncated bool
}

// EnrichmentInfo contains Kubernetes and container runtime metadata attached to events/alerts.
type EnrichmentInfo struct {
	PodName        string            `json:"pod_name,omitempty"`
	Namespace      string            `json:"namespace,omitempty"`
	PodUID         string            `json:"pod_uid,omitempty"`
	NodeName       string            `json:"node_name,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Annotations    map[string]string `json:"annotations,omitempty"`
	ContainerID    string            `json:"container_id,omitempty"`
	ContainerName  string            `json:"container_name,omitempty"`
	ContainerImage string            `json:"container_image,omitempty"`
	// RuntimeSource identifies which enrichment path populated this struct:
	// "k8s", "docker", "containerd", or "crio".
	RuntimeSource string `json:"runtime_source,omitempty"`
}

// SyscallEvent contains syscall tracepoint data.
type SyscallEvent struct {
	Nr   int64 // syscall number
	Ret  int64 // return value (from sys_exit)
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
	Saddr  [16]byte // source IP (IPv4 in first 4 bytes, IPv6 uses full 16)
	Daddr  [16]byte // destination IP (IPv4 in first 4 bytes, IPv6 uses full 16)
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
	// FDPath is the resolved file path for read/write events, populated via fd→path BPF map lookup.
	// For open events FDPath matches Filename; for read/write events Filename would otherwise be empty.
	FDPath string
	// FDPathTruncated is true when the resolved path exceeded 255 bytes and was truncated.
	FDPathTruncated bool
}

// TLSDirection indicates the direction of TLS traffic.
type TLSDirection uint8

const (
	// TLSDirectionWrite indicates outbound TLS data (SSL_write).
	TLSDirectionWrite TLSDirection = 0
	// TLSDirectionRead indicates inbound TLS data (SSL_read).
	TLSDirectionRead TLSDirection = 1
)

// TLSEvent contains TLS plaintext data captured via uprobes.
type TLSEvent struct {
	// Direction indicates whether this is outbound (write) or inbound (read) data.
	Direction TLSDirection
	// DataLen is the actual length of the TLS record (may exceed len(Data)).
	DataLen uint32
	// Data contains the captured plaintext (first 256 bytes).
	Data [256]byte
	// JA3 is the JA3 TLS client fingerprint hash (MD5 hex) computed from the
	// TLS ClientHello handshake message.
	JA3 string
	// JA4 is the JA4 TLS fingerprint (structured hash) computed from the
	// ClientHello.  Successor to JA3, more resistant to evasions.
	JA4 string
	// JA3S is the JA3S server-side fingerprint hash (MD5 hex) computed from the
	// TLS ServerHello handshake message.
	JA3S string
}

// DNSDirection indicates the direction of DNS traffic.
type DNSDirection uint8

const (
	// DNSDirectionQuery indicates an outbound DNS query.
	DNSDirectionQuery DNSDirection = 0
	// DNSDirectionResponse indicates an inbound DNS response.
	DNSDirectionResponse DNSDirection = 1
)

// DNSEvent contains DNS query/response data.
type DNSEvent struct {
	// QName is the query name (domain).
	QName string
	// QType is the query type (A=1, AAAA=28, TXT=16, etc.).
	QType uint16
	// RCode is the response code (0=success, 3=NXDOMAIN, etc.).
	RCode uint16
	// Direction indicates query (outbound) or response (inbound).
	Direction DNSDirection
	// ResponseIPs contains IPv4 addresses from A record responses.
	ResponseIPs []string
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

// ProcessNode represents a single process in an ancestry chain.
type ProcessNode struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
}

// ProcessTree is an ordered ancestry chain from the oldest known ancestor to the
// triggering process, e.g. [systemd] → [kubelet] → [containerd-shim] → [nginx] → [bash] → [curl].
type ProcessTree []ProcessNode

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
	// SpanID is the parent APM span ID extracted from the W3C traceparent header.
	// Set when the alert was triggered for a request carrying OTel trace context.
	SpanID string `json:"span_id,omitempty"`
	// TraceContext carries the full structured trace context including the extraction
	// source. When set, TraceID and SpanID above mirror TraceContext.TraceID and
	// TraceContext.SpanID for backward compatibility.
	TraceContext *TraceContext   `json:"trace_context,omitempty"`
	Enrichment   EnrichmentInfo `json:"enrichment,omitempty"`
	Event      Event                  `json:"-"` // the triggering event (not serialized to store)
	// ProcessTree holds the full ancestor chain for the triggering process.
	// Ordered from oldest known ancestor to the process that fired the alert.
	// Populated by CorrelationEngine when a LineageTracker is configured.
	ProcessTree ProcessTree `json:"process_tree,omitempty"`
	// Fingerprint is a SHA-256 hash for tamper detection (optional)
	Fingerprint string `json:"fingerprint,omitempty"`
	// Action is the enforcement action declared by the matching rule
	// (e.g. "kill", "block", "throttle"). Empty string means "alert only".
	Action string `json:"action,omitempty"`
	// Enforced is true when the rule action was executed by the enforcer.
	Enforced bool `json:"enforced,omitempty"`
	// PreAlertContext holds the most-recent events observed for the triggering PID
	// in the seconds before this alert fired. Only populated when the engine is
	// configured with EnableEventBuffer=true. Provides temporal attack-chain context
	// (e.g. DNS→TCP→file write→execve) for SOC triage without a separate API query.
	PreAlertContext []Event `json:"pre_alert_context,omitempty"`
}

// TraceContext holds OpenTelemetry trace context for propagation.
// Fields follow W3C Trace Context spec (https://www.w3.org/TR/trace-context/).
type TraceContext struct {
	// TraceID is the 32-hex-char trace identifier from the traceparent header.
	TraceID string `json:"trace_id,omitempty"`
	// SpanID is the 16-hex-char parent span identifier from the traceparent header.
	SpanID string `json:"span_id,omitempty"`
	// TraceFlags is the 2-hex-char flags byte from the traceparent header (e.g. "01" = sampled).
	TraceFlags string `json:"trace_flags,omitempty"`
	// TraceState is the optional tracestate header value carrying vendor-specific trace metadata.
	TraceState string `json:"trace_state,omitempty"`
	// Source identifies how the trace context was obtained:
	// "tls_header" — extracted from a W3C traceparent HTTP/gRPC header via TLS uprobe,
	// "environ"    — extracted from /proc/PID/environ (OTel, Datadog, or Jaeger env vars),
	// "otel_sdk"   — injected directly by the OTel SDK (future).
	Source string `json:"source,omitempty"`
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

// PrivescEvent contains privilege escalation data (capability change).
type PrivescEvent struct {
	// OldCaps is the effective capability set before the change (bitmask).
	OldCaps uint64
	// NewCaps is the effective capability set after the change (bitmask).
	NewCaps uint64
}

// NetworkCloseEvent contains TCP connection-close data including duration.
type NetworkCloseEvent struct {
	// Saddr / Daddr / Sport / Dport identify the connection tuple.
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
	Family AddressFamily
	// Duration is how long the connection was open.
	Duration time.Duration
}

// KmodEvent contains kernel module load data.
type KmodEvent struct {
	// ModName is the module name (from kernel_module_request) or filename (from kernel_read_file).
	ModName string
	// FromTmpfs is true when the module is loaded from /tmp or /dev/shm.
	FromTmpfs bool
}

// CgroupEscapeEvent contains data about a process migrating to a different cgroup.
type CgroupEscapeEvent struct {
	// InitCgroupID is the cgroup ID recorded at exec time.
	InitCgroupID uint64
	// NewCgroupID is the destination cgroup ID at migration time.
	NewCgroupID uint64
}

// GPUOpType identifies the type of GPU/CUDA memory operation captured via uprobes.
type GPUOpType uint8

const (
	// GPUOpAlloc indicates a GPU memory allocation (cuMemAlloc_v2 / cudaMalloc).
	GPUOpAlloc GPUOpType = 0
	// GPUOpFree indicates a GPU memory deallocation (cuMemFree_v2 / cudaFree).
	GPUOpFree GPUOpType = 1
	// GPUOpMemcpyHtoD indicates a Host-to-Device memory copy.
	GPUOpMemcpyHtoD GPUOpType = 2
	// GPUOpMemcpyDtoH indicates a Device-to-Host memory copy — primary exfiltration vector.
	GPUOpMemcpyDtoH GPUOpType = 3
	// GPUOpMemcpyDtoD indicates a Device-to-Device memory copy (peer GPU or same GPU).
	GPUOpMemcpyDtoD GPUOpType = 4
	// GPUOpKernelLaunch indicates a GPU kernel launch (cuLaunchKernel).
	GPUOpKernelLaunch GPUOpType = 5
)

// GPUEvent contains CUDA/GPU memory operation data captured via uprobes on libcuda.so / libcudart.so.
// Device-to-Host copies (GPUOpMemcpyDtoH) are the primary exfiltration signal:
// training data lives in GPU memory and must pass through this call to reach the network.
type GPUEvent struct {
	// Op is the GPU operation type (alloc, free, memcpy direction, kernel launch).
	Op GPUOpType
	// DevPtr is the GPU device-memory address involved in the operation.
	DevPtr uint64
	// HostPtr is the host CPU-memory address (only set for HtoD and DtoH copies).
	HostPtr uint64
	// Size is the byte count for the operation (allocation size or transfer size).
	Size uint64
}

// IOUringEvent contains io_uring activity data captured via kprobes
// on io_uring_setup and io_uring_enter. io_uring bypasses traditional
// syscall tracepoints (openat, connect, etc.), making it a blind spot
// for tracepoint-based security agents.
type IOUringEvent struct {
	// Op identifies the io_uring syscall: 0=setup, 1=enter.
	Op uint8
	// Flags from io_uring_setup or io_uring_enter (IORING_SETUP_* / IORING_ENTER_*).
	Flags uint32
	// Fd is the io_uring instance file descriptor (-1 for setup before return).
	Fd int32
	// ToSubmit is the number of submission queue entries to submit (enter only).
	ToSubmit uint32
}

// BPFProgramEvent contains data from monitoring the bpf() syscall.
// Emitted by the BPFMonitorCollector via kprobe/kretprobe on __x64_sys_bpf
// for BPF_PROG_LOAD (cmd=5) and BPF_MAP_CREATE (cmd=0) commands.
type BPFProgramEvent struct {
	// Cmd is the bpf() command number: 0=BPF_MAP_CREATE, 5=BPF_PROG_LOAD.
	Cmd uint32
	// ProgType is the BPF program type for BPF_PROG_LOAD,
	// or the map type for BPF_MAP_CREATE.
	ProgType uint32
	// Ret is the return value of the bpf() syscall: fd on success, negative errno on failure.
	Ret int32
}

// LSMAuditEvent contains an LSM-hook audit record decoded from the lsm_events
// ring buffer written by bpf/lsm.bpf.c. The ai_sandbox hooks emit one of these
// for every would-be-denied (audit mode) or denied (enforce mode) action inside
// a sandboxed cgroup, so a populated LSMAuditEvent is always a policy violation.
type LSMAuditEvent struct {
	// Hook is the LSM hook that produced the record: "file_open",
	// "socket_connect", "task_kill", "bprm_check", "bpf", "ptrace", "mount",
	// or "module".
	Hook string
	// Decision is the action the hook took, matched by the "decision" rule field:
	// "sandbox_audit" (ai_sandbox would-be-deny), "sandbox_deny" (ai_sandbox deny),
	// "audit" (enforcer log-only), or "deny" (enforcer block).
	Decision string
	// Enforced is true when the action was actually denied (-EPERM) rather than
	// only logged.
	Enforced bool
	// Path is the file path for file_open records, or a decoded "host:port" for
	// socket_connect records. Empty for hooks that carry no path.
	Path string
	// TargetPID is the signalled task for task_kill records. For ai_sandbox
	// records it instead carries the matched profile ID (the BPF hook reuses the
	// field), so treat it as opaque outside task_kill.
	TargetPID uint32
}

// CloudAuditEvent contains cloud control-plane audit data from AWS CloudTrail,
// GCP Audit Logs, or Azure Activity Logs.
type CloudAuditEvent struct {
	// Provider identifies the cloud provider: "aws", "gcp", or "azure".
	Provider string
	// Service is the cloud service name, e.g. "iam", "ec2", "gke", "storage".
	Service string
	// Action is the API operation, e.g. "AssumeRole", "GetSecretValue", "pods/exec".
	Action string
	// Principal is the identity that performed the action (ARN, service account email, etc.).
	Principal string
	// ResourceARN is the target resource identifier.
	ResourceARN string
	// SourceIP is the client IP address that initiated the request.
	SourceIP string
	// UserAgent is the HTTP user-agent string from the cloud API request.
	UserAgent string
	// ErrorCode is non-empty when the action was denied or failed.
	// For AWS: the error code from CloudTrail (e.g. "AccessDenied").
	// For GCP: the gRPC status code as a string (e.g. "PERMISSION_DENIED").
	ErrorCode string
	// Region is the cloud region where the event occurred.
	Region string
	// EventID is the provider-assigned event ID used for deduplication.
	EventID string
}

// Reset clears all pointer fields so the Event can be safely returned to a sync.Pool.
// Scalar and fixed-size array fields need not be cleared; they are overwritten on the
// next fill (ToTypesEvent assignment). Pointer fields must be nil'd to avoid keeping
// the inner structs alive after the pooled Event is reused.
func (e *Event) Reset() {
	e.Syscall = nil
	e.Network = nil
	e.File = nil
	e.TLS = nil
	e.DNS = nil
	e.Privesc = nil
	e.NetClose = nil
	e.Kmod = nil
	e.CgroupEsc = nil
	e.GPU = nil
	e.CloudAudit = nil
	e.IOUring = nil
	e.BPFProgram = nil
	e.LSMAudit = nil
	e.TraceContext = nil
	e.Enrichment = nil
	e.ProcArgs = ""
	e.ProcArgsTruncated = false
}

// ProcessProfile represents a learned behavioral profile for a process type.
type ProcessProfile struct {
	Comm          string             `json:"comm"`
	Namespace     string             `json:"namespace,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
	SyscallCounts map[int]float64    `json:"syscall_counts"`
	FileAccess    map[string]float64 `json:"file_access"`
	NetworkPeers  map[string]float64 `json:"network_peers"`
	AnomalyScore  float64            `json:"anomaly_score"`
	SampleCount   int64              `json:"sample_count"`
	Contributions map[string]float64 `json:"contributions,omitempty"`
}
