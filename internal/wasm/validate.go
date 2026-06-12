package wasm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ValidationResult holds the outcome of a plugin ABI check.
type ValidationResult struct {
	Path     string
	Meta     PluginMeta
	OK       bool
	Warnings []string
	Errors   []string
	// DryRunAlerts are the alerts produced by running the plugin against synthetic events.
	DryRunAlerts []types.Alert
}

// requiredExports are the exports that MUST be present for ABI compliance.
var requiredExports = []string{"malloc", "evaluate"}

// recommendedExports are expected on a match; absence is a warning, not an error.
var recommendedExports = []string{"free", "alert_severity", "alert_message_ptr", "alert_message_len"}

// ValidatePlugin loads a single .wasm file, checks its ABI, and optionally
// runs it against syntheticEvents.  If syntheticEvents is nil, the dry-run
// step is skipped.
func ValidatePlugin(ctx context.Context, path string, syntheticEvents []types.Event, logger *slog.Logger) ValidationResult {
	res := ValidationResult{Path: path}

	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("read file: %v", err))
		return res
	}

	meta, metaErr := loadMeta(path)
	if metaErr != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("meta: %v", metaErr))
	}
	res.Meta = meta

	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(256))
	defer rt.Close(ctx) //nolint:errcheck

	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("compile: %v", err))
		return res
	}
	defer compiled.Close(ctx) //nolint:errcheck

	// Inspect exported function names.
	exports := compiled.ExportedFunctions()
	exportSet := make(map[string]bool, len(exports))
	for name := range exports {
		exportSet[name] = true
	}

	for _, req := range requiredExports {
		if !exportSet[req] {
			res.Errors = append(res.Errors, fmt.Sprintf("missing required export: %s", req))
		}
	}
	for _, rec := range recommendedExports {
		if !exportSet[rec] {
			res.Warnings = append(res.Warnings, fmt.Sprintf("missing recommended export: %s", rec))
		}
	}

	if len(res.Errors) > 0 {
		return res
	}

	// Check for ABI version global by instantiating once and reading the global.
	// We do this after required-export checks to skip it on obviously broken plugins.
	checkMod, instErr := rt.InstantiateModule(ctx, compiled,
		wazero.NewModuleConfig().WithName("__abi_check__"))
	if instErr == nil {
		if g := checkMod.ExportedGlobal("ebpf_guard_abi_version"); g == nil {
			res.Warnings = append(res.Warnings, "missing ebpf_guard_abi_version global (ABI v1 assumed)")
		}
		_ = checkMod.Close(ctx)
	}

	// Dry-run: instantiate and evaluate synthetic events.
	if len(syntheticEvents) > 0 {
		engine, engErr := NewEngine(ctx, "", logger, 0)
		if engErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("dry-run engine init: %v", engErr))
		} else {
			defer engine.Close(ctx) //nolint:errcheck

			// Temporarily load just this plugin.
			plugin, pErr := loadPlugin(ctx, engine.rt, path, logger)
			if pErr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("dry-run load: %v", pErr))
			} else {
				engine.plugins = []*Plugin{plugin}
				for _, ev := range syntheticEvents {
					alerts := engine.Evaluate(ctx, ev)
					res.DryRunAlerts = append(res.DryRunAlerts, alerts...)
				}
			}
		}
	}

	res.OK = len(res.Errors) == 0
	return res
}

// FormatValidationResult formats a ValidationResult for human-readable output.
func FormatValidationResult(r ValidationResult) string {
	var sb strings.Builder

	status := "PASS"
	if !r.OK {
		status = "FAIL"
	}
	fmt.Fprintf(&sb, "[%s] %s\n", status, r.Path)
	if r.Meta.ID != "" {
		fmt.Fprintf(&sb, "      id=%s  name=%q  severity=%s  action=%s\n",
			r.Meta.ID, r.Meta.Name, r.Meta.Severity, r.Meta.Action)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&sb, "      ERROR:   %s\n", e)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&sb, "      WARNING: %s\n", w)
	}
	if len(r.DryRunAlerts) > 0 {
		fmt.Fprintf(&sb, "      dry-run: %d alert(s) fired\n", len(r.DryRunAlerts))
		for _, a := range r.DryRunAlerts {
			fmt.Fprintf(&sb, "        - [%s] %s\n", a.Severity, a.Message)
		}
	} else if len(r.DryRunAlerts) == 0 && r.OK {
		fmt.Fprintf(&sb, "      dry-run: no alerts fired against synthetic events\n")
	}
	return sb.String()
}
