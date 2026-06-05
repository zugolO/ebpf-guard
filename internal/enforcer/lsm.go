package enforcer

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// extractFilePath returns the file path from a file-access alert, or "" if
// the event carries no file information.
func extractFilePath(alert types.Alert) string {
	if alert.Event.File == nil {
		return ""
	}
	raw := bytesToString(alert.Event.File.Filename[:])
	p := string(raw)
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
}

// ApplyLSMConfigPaths pre-populates the LSM path blocklist from the
// enforcer.lsm_path_blocklist configuration list.  Call this at startup
// after the LSMCollector is loaded and whenever the config is hot-reloaded.
// Returns nil (no-op) when mgr is nil or LSM is unavailable.
func ApplyLSMConfigPaths(mgr LSMBlocklistManager, paths []string) error {
	if mgr == nil || !mgr.IsAvailable() {
		return nil
	}
	if err := mgr.SetPathBlocklist(paths); err != nil {
		return fmt.Errorf("enforcer/lsm: apply config path blocklist: %w", err)
	}
	return nil
}

// executeLSMBlockFile blocks a specific file path via the LSM path blocklist.
// Used when the triggering alert is a file-access event (EventFileAccess).
func (e *Enforcer) executeLSMBlockFile(ctx context.Context, alert types.Alert) error {
	path := extractFilePath(alert)
	if path == "" {
		return fmt.Errorf("enforcer/lsm: file access alert has no path")
	}

	if e.dryRun {
		e.logger.Info("LSM_BLOCK path (dry run)", "path", path, "rule_id", alert.RuleID)
		return nil
	}

	if e.lsmManager == nil || !e.lsmManager.IsAvailable() {
		return fmt.Errorf("enforcer/lsm: LSM not available for path block of %q", path)
	}

	if err := e.lsmManager.AddPathToBlocklist(path); err != nil {
		return fmt.Errorf("enforcer/lsm: add path %q to blocklist: %w", path, err)
	}
	e.logger.Info("LSM path blocked", "path", path, "rule_id", alert.RuleID)
	return nil
}
