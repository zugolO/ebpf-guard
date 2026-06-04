package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestEventLog_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	el, err := NewEventLog(EventLogConfig{Path: path, MaxSizeBytes: 10 * 1024 * 1024})
	if err != nil {
		t.Fatalf("NewEventLog: %v", err)
	}

	before := time.Now()
	events := []types.Event{
		{Type: types.EventFileAccess, PID: 100},
		{Type: types.EventTCPConnect, PID: 200},
		{Type: types.EventSyscall, PID: 300},
	}
	for _, e := range events {
		if err := el.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := el.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := ReadEventsSince(path, before.Add(-time.Second))
	if err != nil {
		t.Fatalf("ReadEventsSince: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("got %d events, want %d", len(got), len(events))
	}
	for i, e := range got {
		if e.PID != events[i].PID {
			t.Errorf("event[%d]: got PID %d, want %d", i, e.PID, events[i].PID)
		}
	}
}

func TestEventLog_SinceFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	el, err := NewEventLog(EventLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewEventLog: %v", err)
	}
	_ = el.Write(types.Event{PID: 1})
	_ = el.Close()

	// Reading with a future cutoff should return 0 events.
	future := time.Now().Add(time.Hour)
	got, _ := ReadEventsSince(path, future)
	if len(got) != 0 {
		t.Errorf("expected 0 events after future cutoff, got %d", len(got))
	}
}

func TestEventLog_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	// Set a tiny max size to force rotation after the first write.
	el, err := NewEventLog(EventLogConfig{Path: path, MaxSizeBytes: 1})
	if err != nil {
		t.Fatalf("NewEventLog: %v", err)
	}
	_ = el.Write(types.Event{PID: 1})
	_ = el.Write(types.Event{PID: 2})
	_ = el.Close()

	// The .prev file should exist after rotation.
	if _, err := os.Stat(path + ".prev"); err != nil {
		t.Errorf("expected .prev file after rotation, got: %v", err)
	}
}

func TestReadEventsSince_MissingFile(t *testing.T) {
	events, err := ReadEventsSince("/nonexistent/path/events.jsonl", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error on missing file: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events from missing file, got %d", len(events))
	}
}
