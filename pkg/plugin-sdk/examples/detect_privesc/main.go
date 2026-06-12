// detect_privesc is a minimal ebpf-guard WASM plugin that alerts whenever a
// process gains the CAP_SYS_ADMIN capability (bit 21).
//
// Build with TinyGo (requires TinyGo 0.33+):
//
//	tinygo build -o detect_privesc.wasm -target wasi .
//
// Then copy detect_privesc.wasm (and optionally detect_privesc.meta.yaml)
// to your rules/custom/ directory and restart or hot-reload the agent.
package main

import (
	sdk "github.com/zugolO/ebpf-guard/pkg/plugin-sdk"
)

func main() {}

func init() {
	sdk.Register(sdk.HandlerFunc(detectPrivesc))
}

// capSysAdmin is bit 21 of the Linux capability bitmask.
const capSysAdmin uint64 = 1 << 21

func detectPrivesc(e *sdk.Event) *sdk.Alert {
	if e.Type != sdk.EventPrivesc || e.Privesc == nil {
		return nil
	}
	gainedCaps := e.Privesc.NewCaps &^ e.Privesc.OldCaps
	if gainedCaps&capSysAdmin == 0 {
		return nil
	}
	return sdk.Alertf(sdk.SeverityCritical,
		"process %s (pid %d) gained CAP_SYS_ADMIN", e.Comm, e.PID)
}
