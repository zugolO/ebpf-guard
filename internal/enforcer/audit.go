// Package enforcer provides audit logging for enforcement actions.
package enforcer

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLogger writes enforcement audit entries to persistent storage.
type AuditLogger struct {
	logger   *slog.Logger
	file     *os.File
	encoder  *json.Encoder
	mu       sync.Mutex
	path     string
	maxSize  int64 // Maximum file size in bytes before rotation
	maxFiles int   // Maximum number of rotated files to keep
}

// AuditLoggerConfig configures the audit logger.
type AuditLoggerConfig struct {
	// Path is the file path for audit log
	Path string
	// MaxSize is the maximum file size in MB before rotation (default: 100)
	MaxSize int
	// MaxFiles is the maximum number of rotated files to keep (default: 5)
	MaxFiles int
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(logger *slog.Logger, cfg AuditLoggerConfig) (*AuditLogger, error) {
	if cfg.Path == "" {
		cfg.Path = "/var/log/ebpf-guard/audit.log"
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 100 // 100 MB
	}
	if cfg.MaxFiles == 0 {
		cfg.MaxFiles = 5
	}

	// Ensure directory exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("audit logger: create directory: %w", err)
	}

	// Open log file (append mode)
	file, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("audit logger: open file: %w", err)
	}

	al := &AuditLogger{
		logger:   logger.With("component", "audit_logger"),
		file:     file,
		encoder:  json.NewEncoder(file),
		path:     cfg.Path,
		maxSize:  int64(cfg.MaxSize) * 1024 * 1024,
		maxFiles: cfg.MaxFiles,
	}

	al.logger.Info("audit logger initialized",
		"path", cfg.Path,
		"max_size_mb", cfg.MaxSize,
		"max_files", cfg.MaxFiles,
	)

	return al, nil
}

// Write writes an audit entry to the log.
func (al *AuditLogger) Write(entry AuditEntry) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Check if rotation is needed
	if err := al.checkRotation(); err != nil {
		return fmt.Errorf("audit rotation: %w", err)
	}

	// Write JSON entry
	if err := al.encoder.Encode(entry); err != nil {
		return fmt.Errorf("audit encode: %w", err)
	}

	// Ensure write is flushed to disk
	if err := al.file.Sync(); err != nil {
		al.logger.Warn("failed to sync audit log", "error", err)
	}

	return nil
}

// checkRotation rotates the log file if it exceeds max size.
func (al *AuditLogger) checkRotation() error {
	info, err := al.file.Stat()
	if err != nil {
		return fmt.Errorf("stat audit file: %w", err)
	}

	if info.Size() < al.maxSize {
		return nil
	}

	// Close current file
	if err := al.file.Close(); err != nil {
		return fmt.Errorf("close audit file for rotation: %w", err)
	}

	// Rotate files: audit.log -> audit.log.1 -> audit.log.2 -> ...
	for i := al.maxFiles - 1; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", al.path, i)
		newPath := fmt.Sprintf("%s.%d", al.path, i+1)

		// Remove oldest file if it exists
		if i == al.maxFiles-1 {
			os.Remove(newPath)
		}

		// Rename if old exists
		if _, err := os.Stat(oldPath); err == nil {
			if err := os.Rename(oldPath, newPath); err != nil {
				al.logger.Warn("failed to rotate audit file",
					"from", oldPath,
					"to", newPath,
					"error", err,
				)
			}
		}
	}

	// Rename current to .1
	if err := os.Rename(al.path, al.path+".1"); err != nil {
		al.logger.Warn("failed to rotate current audit file", "error", err)
	}

	// Open new file
	file, err := os.OpenFile(al.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open new audit file: %w", err)
	}

	al.file = file
	al.encoder = json.NewEncoder(file)

	al.logger.Info("audit log rotated",
		"path", al.path,
		"previous_size_mb", info.Size()/1024/1024,
	)

	return nil
}

// Close closes the audit logger.
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// AuditChannel returns a channel for receiving audit entries.
// This can be passed to the Enforcer config.
func (al *AuditLogger) AuditChannel(bufferSize int) chan<- AuditEntry {
	ch := make(chan AuditEntry, bufferSize)
	go al.processAuditChannel(ch)
	return ch
}

// processAuditChannel processes audit entries from the channel.
func (al *AuditLogger) processAuditChannel(ch <-chan AuditEntry) {
	for entry := range ch {
		if err := al.Write(entry); err != nil {
			al.logger.Error("failed to write audit entry",
				"error", err,
				"action", entry.Action,
				"pid", entry.PID,
			)
		}
	}
}

// ReadAuditLog reads audit entries from the log file.
func ReadAuditLog(path string) ([]AuditEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	var entries []AuditEntry
	decoder := json.NewDecoder(file)

	for {
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("decode audit entry: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// QueryAuditLog queries audit entries with filters.
func QueryAuditLog(path string, since time.Time, action ActionType, pid uint32) ([]AuditEntry, error) {
	entries, err := ReadAuditLog(path)
	if err != nil {
		return nil, err
	}

	var filtered []AuditEntry
	for _, entry := range entries {
		if !since.IsZero() && entry.Timestamp.Before(since) {
			continue
		}
		if action != "" && entry.Action != action {
			continue
		}
		if pid != 0 && entry.PID != pid {
			continue
		}
		filtered = append(filtered, entry)
	}

	return filtered, nil
}

// AuditStats returns statistics about audit entries.
type AuditStats struct {
	TotalEntries   int
	ByAction       map[ActionType]int
	ByRuleID       map[string]int
	SuccessCount   int
	FailureCount   int
	FirstTimestamp time.Time
	LastTimestamp  time.Time
}

// GetStats returns statistics for the audit log.
func (al *AuditLogger) GetStats() (*AuditStats, error) {
	entries, err := ReadAuditLog(al.path)
	if err != nil {
		return nil, err
	}

	stats := &AuditStats{
		TotalEntries: len(entries),
		ByAction:     make(map[ActionType]int),
		ByRuleID:     make(map[string]int),
	}

	for _, entry := range entries {
		stats.ByAction[entry.Action]++
		stats.ByRuleID[entry.RuleID]++
		if entry.Success {
			stats.SuccessCount++
		} else {
			stats.FailureCount++
		}

		if stats.FirstTimestamp.IsZero() || entry.Timestamp.Before(stats.FirstTimestamp) {
			stats.FirstTimestamp = entry.Timestamp
		}
		if entry.Timestamp.After(stats.LastTimestamp) {
			stats.LastTimestamp = entry.Timestamp
		}
	}

	return stats, nil
}
