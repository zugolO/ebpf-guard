// Package store provides pluggable storage backends for alerts and profiles.
package store

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// EventLogConfig configures the JSONL event log used for rule replay.
type EventLogConfig struct {
	// Path is the file path for the event log.
	Path string
	// MaxSizeBytes is the maximum file size before rotation (default 100 MB).
	MaxSizeBytes int64
}

// eventLogEntry is the JSONL record written per event.
type eventLogEntry struct {
	Timestamp time.Time   `json:"ts"`
	Event     types.Event `json:"event"`
}

// EventLog writes raw events to a JSONL file for later replay.
// It is safe for concurrent use.
type EventLog struct {
	cfg     EventLogConfig
	mu      sync.Mutex
	file    *os.File
	written int64
}

// NewEventLog opens (or creates) the event log file.
func NewEventLog(cfg EventLogConfig) (*EventLog, error) {
	if cfg.MaxSizeBytes == 0 {
		cfg.MaxSizeBytes = 100 * 1024 * 1024
	}
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("event log: open %s: %w", cfg.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("event log: stat: %w", err)
	}
	return &EventLog{cfg: cfg, file: f, written: info.Size()}, nil
}

// Write serialises an event to the log. Thread-safe.
func (el *EventLog) Write(e types.Event) error {
	entry := eventLogEntry{Timestamp: time.Now(), Event: e}
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("event log: marshal: %w", err)
	}
	b = append(b, '\n')

	el.mu.Lock()
	defer el.mu.Unlock()

	if el.written+int64(len(b)) > el.cfg.MaxSizeBytes {
		if err := el.rotate(); err != nil {
			return err
		}
	}
	n, err := el.file.Write(b)
	el.written += int64(n)
	return err
}

// rotate renames the current file to .prev and opens a fresh one.
func (el *EventLog) rotate() error {
	_ = el.file.Close()
	_ = os.Rename(el.cfg.Path, el.cfg.Path+".prev")
	f, err := os.OpenFile(el.cfg.Path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("event log: rotate create: %w", err)
	}
	el.file = f
	el.written = 0
	return nil
}

// Close flushes and closes the log file.
func (el *EventLog) Close() error {
	el.mu.Lock()
	defer el.mu.Unlock()
	if el.file != nil {
		return el.file.Close()
	}
	return nil
}

// ReadEventsSince reads all events logged after `since` from the log at `path`.
// It also checks path+".prev" for events that may have been rotated away.
func ReadEventsSince(path string, since time.Time) ([]types.Event, error) {
	var events []types.Event
	// Read older rotated file first.
	prev, _ := readEventFile(path+".prev", since)
	events = append(events, prev...)
	cur, err := readEventFile(path, since)
	events = append(events, cur...)
	return events, err
}

func readEventFile(path string, since time.Time) ([]types.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("event log: open %s: %w", path, err)
	}
	defer f.Close()

	var events []types.Event
	dec := json.NewDecoder(f)
	for {
		var entry eventLogEntry
		if err := dec.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			continue // skip malformed lines
		}
		if entry.Timestamp.After(since) {
			events = append(events, entry.Event)
		}
	}
	return events, nil
}
