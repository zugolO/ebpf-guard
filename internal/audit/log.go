// Package audit provides append-only JSONL audit logging for enforcement actions.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const rotateSize = 100 * 1024 * 1024 // 100 MB

// Entry is one enforcement audit record.
// JSON field names match the spec so consumers can rely on them without schema evolution.
type Entry struct {
	TS       time.Time `json:"ts"`
	Action   string    `json:"action"`
	PID      uint32    `json:"pid"`
	Rule     string    `json:"rule"`
	Comm     string    `json:"comm"`
	Enforced bool      `json:"enforced"`
}

// Logger writes enforcement audit entries to an append-only JSONL file.
// When the file grows beyond 100 MB it is renamed to <path>.1 and a new file is opened.
// All public methods are safe for concurrent use.
type Logger struct {
	path    string
	file    *os.File
	enc     *json.Encoder
	mu      sync.Mutex
	maxSize int64
}

// New opens (or creates) the JSONL audit log at path.
// The parent directory is created with mode 0750 if it does not exist.
func New(path string) (*Logger, error) {
	return newLogger(path, rotateSize)
}

// newLogger is the internal constructor that accepts a custom rotation threshold.
// Used by tests to trigger rotation without writing 100 MB of data.
func newLogger(path string, maxSize int64) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("audit log: mkdir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("audit log: open %s: %w", path, err)
	}
	return &Logger{path: path, file: f, enc: json.NewEncoder(f), maxSize: maxSize}, nil
}

// Log appends one entry to the JSONL file.
// If the file exceeds 100 MB it is rotated before the write.
func (l *Logger) Log(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.maybeRotate(); err != nil {
		return err
	}
	return l.enc.Encode(e)
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// maybeRotate renames the current file to <path>.1 and opens a fresh file
// when the current file has grown past l.maxSize. Called under l.mu.
func (l *Logger) maybeRotate() error {
	info, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("audit log: stat: %w", err)
	}
	if info.Size() < l.maxSize {
		return nil
	}
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("audit log: close for rotation: %w", err)
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return fmt.Errorf("audit log: rename for rotation: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("audit log: open after rotation: %w", err)
	}
	l.file = f
	l.enc = json.NewEncoder(f)
	return nil
}
