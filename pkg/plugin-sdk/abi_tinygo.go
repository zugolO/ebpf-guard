//go:build tinygo && wasm

package pluginsdk

// This file contains the WASM ABI exports the host calls on every event.  The
// pointer/length conversions here treat host-supplied uintptr values as offsets
// into the plugin's WASM linear memory — a pattern that is only valid (and only
// compiled) when building a plugin with TinyGo for a wasm target.  It is gated
// behind the `tinygo` build tag so the host's `go build`/`go vet ./...` on a
// normal target does not compile these conversions (which `go vet` correctly
// flags as misuse of unsafe.Pointer outside the WASM context).

import (
	"encoding/json"
	"unsafe"
)

// module-level state written by evaluate(), read by alert_* exports.
var (
	lastAlert *Alert
	alertBuf  []byte
)

// ── WASM ABI exports ─────────────────────────────────────────────────────────
// These functions are exported to the host under the standard ABI.
// TinyGo will export them automatically when they are package-level functions
// in main (or called from exported functions in main).

//export malloc
func pluginMalloc(size uint32) uintptr {
	if size == 0 {
		// Avoid &buf[0] panicking on an empty slice; a zero-length
		// allocation has no valid address for the host to write into.
		return 0
	}
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
