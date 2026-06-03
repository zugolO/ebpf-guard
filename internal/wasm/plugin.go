// Package wasm provides a WebAssembly-based detection plugin system for ebpf-guard.
//
// Plugins are .wasm binaries placed in the custom rules directory (rules/custom/).
// Each plugin may have a companion .meta.yaml manifest file that provides metadata.
// Plugins that do not have a manifest derive their ID and name from the filename.
//
// # Plugin ABI
//
// A plugin WASM module must export the following functions:
//
//	malloc(size i32) i32          — allocate `size` bytes in linear memory, return pointer
//	free(ptr i32)                 — release memory previously allocated by malloc
//	evaluate(ptr i32, len i32) i32 — evaluate event JSON at [ptr:ptr+len], return 1=match, 0=no match
//
// If evaluate returns 1 (match), the host also calls:
//
//	alert_severity() i32          — 0=warning, 1=critical
//	alert_message_ptr() i32       — pointer to UTF-8 alert message in plugin memory
//	alert_message_len() i32       — byte length of alert message (max 4096)
//
// The event JSON format passed to evaluate:
//
//	{
//	  "type": 2,           // EventType constant (1=syscall, 2=network, 3=file, 4=tls, 5=dns)
//	  "pid": 1234,
//	  "ppid": 1,
//	  "uid": 0,
//	  "comm": "nginx",
//	  "parent_comm": "containerd-shim",
//	  "network": { "saddr": "10.0.0.1", "daddr": "1.2.3.4", "sport": 54321, "dport": 443 },
//	  "file": { "filename": "/etc/shadow", "flags": 0, "op": 0 },
//	  "dns": { "qname": "example.com", "qtype": 1 },
//	  "tls": { "direction": 0, "data_len": 256 }
//	}
package wasm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"gopkg.in/yaml.v3"
)

const (
	// maxMessageLen is the maximum alert message length read from plugin memory.
	maxMessageLen = 4096
)

// EvalResult is the result of a plugin evaluation.
type EvalResult struct {
	Matched  bool
	Message  string
	Severity types.Severity
}

// PluginMeta is the companion YAML manifest for a WASM plugin.
// Place it at <plugin_name>.meta.yaml alongside the .wasm file.
type PluginMeta struct {
	ID          string         `yaml:"id"`
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Severity    types.Severity `yaml:"severity"`
	Action      string         `yaml:"action"`
	Tags        []string       `yaml:"tags"`
}

// Plugin wraps a compiled WASM module with its metadata and provides
// thread-safe evaluation via per-call module instantiation.
type Plugin struct {
	meta        PluginMeta
	rt          wazero.Runtime
	compiled    wazero.CompiledModule
	logger      *slog.Logger
	instanceSeq atomic.Uint64
}

// ID returns the plugin identifier from its manifest.
func (p *Plugin) ID() string { return p.meta.ID }

// Meta returns a copy of the plugin manifest.
func (p *Plugin) Meta() PluginMeta { return p.meta }

// Evaluate instantiates a fresh module instance, writes the event JSON into
// the plugin's linear memory, calls evaluate(), and reads back the result.
//
// A fresh instance is used per call to guarantee full isolation — no state leaks
// between events even if multiple goroutines evaluate the same plugin concurrently.
func (p *Plugin) Evaluate(ctx context.Context, eventJSON []byte) (EvalResult, error) {
	name := fmt.Sprintf("%s-%d", p.meta.ID, p.instanceSeq.Add(1))
	mod, err := p.rt.InstantiateModule(ctx, p.compiled,
		wazero.NewModuleConfig().WithName(name))
	if err != nil {
		return EvalResult{}, fmt.Errorf("instantiate plugin %q: %w", p.meta.ID, err)
	}
	defer mod.Close(ctx)

	mem := mod.Memory()
	if mem == nil {
		return EvalResult{}, fmt.Errorf("plugin %q: no exported memory", p.meta.ID)
	}

	mallocFn := mod.ExportedFunction("malloc")
	freeFn := mod.ExportedFunction("free")
	evaluateFn := mod.ExportedFunction("evaluate")

	if mallocFn == nil || evaluateFn == nil {
		return EvalResult{}, fmt.Errorf("plugin %q: missing required exports (malloc, evaluate)", p.meta.ID)
	}

	// Allocate linear memory for event JSON inside the plugin.
	allocResults, err := mallocFn.Call(ctx, uint64(len(eventJSON)))
	if err != nil {
		return EvalResult{}, fmt.Errorf("plugin %q malloc(%d): %w", p.meta.ID, len(eventJSON), err)
	}
	ptr := uint32(allocResults[0])
	if !mem.Write(ptr, eventJSON) {
		return EvalResult{}, fmt.Errorf("plugin %q: write to linear memory failed (ptr=%d, len=%d)", p.meta.ID, ptr, len(eventJSON))
	}

	// Evaluate the event.
	evalResults, evalErr := evaluateFn.Call(ctx, uint64(ptr), uint64(len(eventJSON)))

	// Always free even on error.
	if freeFn != nil {
		freeFn.Call(ctx, uint64(ptr)) //nolint:errcheck
	}

	if evalErr != nil {
		return EvalResult{}, fmt.Errorf("plugin %q evaluate: %w", p.meta.ID, evalErr)
	}

	if evalResults[0] == 0 {
		return EvalResult{Matched: false}, nil
	}

	return p.readAlert(ctx, mod), nil
}

// readAlert reads the alert severity and message from the plugin's linear memory.
func (p *Plugin) readAlert(ctx context.Context, mod api.Module) EvalResult {
	result := EvalResult{
		Matched:  true,
		Severity: p.meta.Severity,
		Message:  p.meta.Description,
	}

	mem := mod.Memory()

	if sevFn := mod.ExportedFunction("alert_severity"); sevFn != nil {
		if sevResults, err := sevFn.Call(ctx); err == nil {
			if sevResults[0] == 1 {
				result.Severity = types.SeverityCritical
			} else {
				result.Severity = types.SeverityWarning
			}
		}
	}

	msgPtrFn := mod.ExportedFunction("alert_message_ptr")
	msgLenFn := mod.ExportedFunction("alert_message_len")
	if msgPtrFn != nil && msgLenFn != nil {
		ptrRes, perr := msgPtrFn.Call(ctx)
		lenRes, lerr := msgLenFn.Call(ctx)
		if perr == nil && lerr == nil {
			msgPtr := uint32(ptrRes[0])
			msgLen := uint32(lenRes[0])
			if msgLen > 0 && msgLen <= maxMessageLen {
				if msgBytes, ok := mem.Read(msgPtr, msgLen); ok {
					result.Message = string(msgBytes)
				}
			}
		}
	}

	return result
}

// Close releases the compiled WASM module.
func (p *Plugin) Close(ctx context.Context) error {
	return p.compiled.Close(ctx)
}

// loadPlugin compiles a WASM file and loads its metadata.
func loadPlugin(ctx context.Context, rt wazero.Runtime, path string, logger *slog.Logger) (*Plugin, error) {
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read wasm: %w", err)
	}

	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("compile wasm %q: %w", filepath.Base(path), err)
	}

	meta, err := loadMeta(path)
	if err != nil {
		compiled.Close(ctx) //nolint:errcheck
		return nil, fmt.Errorf("load meta for %q: %w", filepath.Base(path), err)
	}

	return &Plugin{
		meta:     meta,
		rt:       rt,
		compiled: compiled,
		logger:   logger.With("plugin", meta.ID),
	}, nil
}

// loadMeta reads the companion .meta.yaml manifest for a WASM plugin.
// If the manifest does not exist, defaults are derived from the filename.
func loadMeta(wasmPath string) (PluginMeta, error) {
	base := strings.TrimSuffix(filepath.Base(wasmPath), ".wasm")
	meta := PluginMeta{
		ID:       base,
		Name:     base,
		Severity: types.SeverityWarning,
		Action:   "alert",
	}

	metaPath := strings.TrimSuffix(wasmPath, ".wasm") + ".meta.yaml"
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return meta, nil
		}
		return meta, fmt.Errorf("read %q: %w", metaPath, err)
	}

	if err := yaml.Unmarshal(data, &meta); err != nil {
		return meta, fmt.Errorf("parse %q: %w", metaPath, err)
	}
	if meta.ID == "" {
		meta.ID = base
	}
	if meta.Severity == "" {
		meta.Severity = types.SeverityWarning
	}
	if meta.Action == "" {
		meta.Action = "alert"
	}
	return meta, nil
}

// SerializeEvent converts a types.Event to the JSON format expected by WASM plugins.
// Only the fields relevant to the event type are included to keep payloads small.
func SerializeEvent(e types.Event) ([]byte, error) {
	m := map[string]interface{}{
		"type":        int(e.Type),
		"timestamp":   e.Timestamp,
		"pid":         e.PID,
		"tgid":        e.TGID,
		"ppid":        e.PPID,
		"uid":         e.UID,
		"comm":        strings.TrimRight(string(e.Comm[:]), "\x00"),
		"parent_comm": strings.TrimRight(string(e.ParentComm[:]), "\x00"),
	}
	if e.Network != nil {
		m["network"] = map[string]interface{}{
			"saddr":  formatIP(e.Network.Saddr, e.Network.Family),
			"daddr":  formatIP(e.Network.Daddr, e.Network.Family),
			"sport":  e.Network.Sport,
			"dport":  e.Network.Dport,
			"proto":  e.Network.Proto,
			"family": int(e.Network.Family),
		}
	}
	if e.File != nil {
		m["file"] = map[string]interface{}{
			"filename": strings.TrimRight(string(e.File.Filename[:]), "\x00"),
			"flags":    e.File.Flags,
			"mode":     e.File.Mode,
			"op":       e.File.Op,
		}
	}
	if e.DNS != nil {
		m["dns"] = map[string]interface{}{
			"qname":     e.DNS.QName,
			"qtype":     e.DNS.QType,
			"rcode":     e.DNS.RCode,
			"direction": int(e.DNS.Direction),
		}
	}
	if e.TLS != nil {
		m["tls"] = map[string]interface{}{
			"direction": int(e.TLS.Direction),
			"data_len":  e.TLS.DataLen,
		}
	}
	if e.Syscall != nil {
		m["syscall"] = map[string]interface{}{
			"nr":  e.Syscall.Nr,
			"ret": e.Syscall.Ret,
		}
	}
	return json.Marshal(m)
}

// formatIP formats a 16-byte IP field as a dotted-decimal or colon-hex string.
func formatIP(addr [16]byte, family types.AddressFamily) string {
	if family == types.AFInet {
		return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		addr[0], addr[1], addr[2], addr[3],
		addr[4], addr[5], addr[6], addr[7],
		addr[8], addr[9], addr[10], addr[11],
		addr[12], addr[13], addr[14], addr[15])
}
