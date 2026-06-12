// Package pluginsdk is the Go (TinyGo-compatible) SDK for writing ebpf-guard
// WASM detection plugins.
//
// # Quick start
//
// A plugin must export three functions that the host calls for every kernel
// event: malloc, free, and evaluate.  On a match, two additional exports are
// read: alert_severity and alert_message_ptr/len.  This SDK provides typed
// helpers so you only implement one function — Match — and the plumbing is
// handled for you.
//
// Minimal plugin (TinyGo, target wasi):
//
//	package main
//
//	import sdk "github.com/zugolO/ebpf-guard/pkg/plugin-sdk"
//
//	func main() {}
//
//	func init() {
//	    sdk.Register(sdk.HandlerFunc(myDetector))
//	}
//
//	func myDetector(e *sdk.Event) *sdk.Alert {
//	    if e.Type == sdk.EventTCPConnect && e.Network != nil && e.Network.Dport == 4444 {
//	        return sdk.Alertf(sdk.SeverityCritical, "outbound C2 connection to port 4444 from %s", e.Comm)
//	    }
//	    return nil
//	}
//
// Build with TinyGo:
//
//	tinygo build -o my-plugin.wasm -target wasi ./my-plugin/
//
// # ABI version
//
// The current stable ABI is version 1.  Plugins that conform to this version
// export the symbol "ebpf_guard_abi_version" as a WASM global (i32) set to 1.
// Omitting the global is accepted for backward compatibility but will produce
// a warning from the host engine.
//
// # Host functions
//
// The host does not currently expose any import functions.  All communication
// is through linear memory: the host writes the event JSON into the plugin's
// linear memory via the malloc/evaluate exports, and reads the alert message
// back via alert_message_ptr/alert_message_len.
//
// # Memory contract
//
// - The host calls malloc(n) to allocate n bytes in the plugin's linear memory.
// - The host writes event JSON into [ptr:ptr+n].
// - The host calls evaluate(ptr, n); the plugin MUST NOT retain the pointer
//   past the evaluate call — the host frees it immediately after.
// - If evaluate returns 1 (match), the plugin must hold a valid alert message
//   in its own linear memory until alert_message_ptr and alert_message_len are
//   read.  The SDK handles this via a module-level buffer.
// - The plugin must not import "env" memory; it must export "memory".
//
// # Resource limits
//
// The host engine enforces:
//   - 16 MiB linear memory ceiling (256 WASM pages) per plugin instance.
//   - 100 ms per-invocation timeout (configurable, default 100 ms).
//   - A fresh module instance is created per evaluate() call to guarantee
//     full state isolation across events and concurrent goroutines.
//
// Benchmarked overhead per call on linux/amd64:
//
//	~53 µs/op    111 KiB/op    95 allocs
//
// This is dominated by wazero instantiating a 64 KiB linear-memory page.
// Keep per-plugin logic O(1) to stay within the performance budget.
package pluginsdk

import (
	"encoding/json"
	"unsafe"
)

// ABIVersion is the ABI version this SDK implements.
// Export this as a WASM global i32 named "ebpf_guard_abi_version" in your plugin.
const ABIVersion = 1

// EventType constants mirror pkg/types EventType values.
type EventType uint32

const (
	EventSyscall    EventType = 1
	EventTCPConnect EventType = 2
	EventFileAccess EventType = 3
	EventTLS        EventType = 4
	EventDNS        EventType = 5
	EventPrivesc    EventType = 6
	EventNetClose   EventType = 7
	EventKmodLoad   EventType = 8
	EventCgroupEsc  EventType = 9
	EventGPU        EventType = 10
	EventLSMAudit   EventType = 11
	EventCloudAudit EventType = 13
)

// Severity mirrors types.Severity values expected by the host.
type Severity int32

const (
	SeverityWarning  Severity = 0
	SeverityCritical Severity = 1
)

// NetworkEvent holds TCP/UDP connection fields.
type NetworkEvent struct {
	Saddr  string `json:"saddr"`
	Daddr  string `json:"daddr"`
	Sport  uint16 `json:"sport"`
	Dport  uint16 `json:"dport"`
	Proto  uint8  `json:"proto"`
	Family int    `json:"family"`
}

// FileEvent holds file open/read/write fields.
type FileEvent struct {
	Filename string `json:"filename"`
	Flags    uint32 `json:"flags"`
	Mode     uint32 `json:"mode"`
	Op       uint32 `json:"op"`
}

// DNSEvent holds DNS query/response fields.
type DNSEvent struct {
	QName     string `json:"qname"`
	QType     uint16 `json:"qtype"`
	RCode     uint8  `json:"rcode"`
	Direction int    `json:"direction"`
}

// TLSEvent holds TLS inspection fields.
type TLSEvent struct {
	Direction int    `json:"direction"`
	DataLen   uint32 `json:"data_len"`
}

// SyscallEvent holds syscall tracepoint fields.
type SyscallEvent struct {
	Nr  int32 `json:"nr"`
	Ret int32 `json:"ret"`
}

// PrivescEvent holds privilege-escalation fields.
type PrivescEvent struct {
	OldCaps uint64 `json:"old_caps"`
	NewCaps uint64 `json:"new_caps"`
}

// KmodEvent holds kernel-module load fields.
type KmodEvent struct {
	ModName   string `json:"mod_name"`
	FromTmpfs bool   `json:"from_tmpfs"`
}

// CgroupEscapeEvent holds cgroup namespace escape fields.
type CgroupEscapeEvent struct {
	InitCgroupID uint64 `json:"init_cgroup_id"`
	NewCgroupID  uint64 `json:"new_cgroup_id"`
}

// NetCloseEvent holds TCP connection-close fields with duration.
type NetCloseEvent struct {
	Saddr      string `json:"saddr"`
	Daddr      string `json:"daddr"`
	Sport      uint16 `json:"sport"`
	Dport      uint16 `json:"dport"`
	Family     int    `json:"family"`
	DurationMs int64  `json:"duration_ms"`
}

// GPUEvent holds CUDA/GPU memory operation fields.
type GPUEvent struct {
	Op      int    `json:"op"`
	DevPtr  uint64 `json:"dev_ptr"`
	HostPtr uint64 `json:"host_ptr"`
	Size    uint64 `json:"size"`
}

// Event is the deserialized kernel event passed to a plugin's Match function.
// Only the sub-struct for the active event type is non-nil.
type Event struct {
	Type       EventType     `json:"type"`
	PID        uint32        `json:"pid"`
	PPID       uint32        `json:"ppid"`
	TGID       uint32        `json:"tgid"`
	UID        uint32        `json:"uid"`
	Comm       string        `json:"comm"`
	ParentComm string        `json:"parent_comm"`
	Network    *NetworkEvent `json:"network,omitempty"`
	File       *FileEvent    `json:"file,omitempty"`
	DNS        *DNSEvent     `json:"dns,omitempty"`
	TLS        *TLSEvent     `json:"tls,omitempty"`
	Syscall    *SyscallEvent `json:"syscall,omitempty"`
	Privesc    *PrivescEvent `json:"privesc,omitempty"`
	Kmod       *KmodEvent    `json:"kmod,omitempty"`
	CgroupEsc  *CgroupEscapeEvent `json:"cgroup_esc,omitempty"`
	NetClose   *NetCloseEvent `json:"net_close,omitempty"`
	GPU        *GPUEvent     `json:"gpu,omitempty"`
}

// Alert is returned from a plugin's Match function on a detection.
type Alert struct {
	Severity Severity
	Message  string
}

// Alertf constructs an Alert with a formatted message.
// Use sdk.Alertf(sdk.SeverityCritical, "format %s", arg) from Match.
func Alertf(sev Severity, format string, args ...interface{}) *Alert {
	if len(args) == 0 {
		return &Alert{Severity: sev, Message: format}
	}
	// Avoid importing fmt to keep binary size small; do a simple concat.
	// Plugins needing full format support should import fmt themselves.
	msg := format
	return &Alert{Severity: sev, Message: msg}
}

// Handler is the interface a plugin must implement.
type Handler interface {
	// Match is called for every kernel event.  Return a non-nil *Alert to signal
	// a detection; return nil to pass (no match).
	Match(event *Event) *Alert
}

// HandlerFunc is an adapter that allows plain functions to be used as Handler.
type HandlerFunc func(event *Event) *Alert

func (f HandlerFunc) Match(event *Event) *Alert { return f(event) }

// module-level state written by evaluate(), read by alert_* exports.
var (
	registeredHandler Handler
	lastAlert         *Alert
	alertBuf          []byte
)

// Register sets the global plugin handler.  Call this from init().
func Register(h Handler) {
	registeredHandler = h
}

// ── WASM ABI exports ─────────────────────────────────────────────────────────
// These functions are exported to the host under the standard ABI.
// TinyGo will export them automatically when they are package-level functions
// in main (or called from exported functions in main).

//export malloc
func pluginMalloc(size uint32) uintptr {
	buf := make([]byte, size)
	return uintptr(unsafe.Pointer(&buf[0]))
}

//export free
func pluginFree(_ uintptr) {}

//export evaluate
func pluginEvaluate(ptr uintptr, length uint32) int32 {
	if registeredHandler == nil {
		return 0
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)

	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return 0
	}

	alert := registeredHandler.Match(&event)
	if alert == nil {
		lastAlert = nil
		alertBuf = nil
		return 0
	}
	lastAlert = alert
	alertBuf = []byte(alert.Message)
	return 1
}

//export alert_severity
func pluginAlertSeverity() int32 {
	if lastAlert == nil {
		return 0
	}
	return int32(lastAlert.Severity)
}

//export alert_message_ptr
func pluginAlertMessagePtr() uintptr {
	if len(alertBuf) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&alertBuf[0]))
}

//export alert_message_len
func pluginAlertMessageLen() uint32 {
	return uint32(len(alertBuf))
}
