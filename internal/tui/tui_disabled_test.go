//go:build !tui

package tui

import (
	"context"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNewFeedReturnsNonNil(t *testing.T) {
	f := NewFeed()
	if f == nil {
		t.Fatal("NewFeed() returned nil")
	}
}

func TestPushAlertNoOp(t *testing.T) {
	f := NewFeed()
	// Should not panic and should not retain anything.
	f.PushAlert(types.Alert{RuleID: "r1", Severity: "critical"})

	alerts, events, stats := f.Snapshot(10, 10)
	if len(alerts) != 0 {
		t.Errorf("expected no alerts after PushAlert on stub, got %d", len(alerts))
	}
	if len(events) != 0 {
		t.Errorf("expected no events, got %d", len(events))
	}
	if stats.TotalAlerts != 0 {
		t.Errorf("expected TotalAlerts=0, got %d", stats.TotalAlerts)
	}
}

func TestPushEventNoOp(t *testing.T) {
	f := NewFeed()
	f.PushEvent(types.Event{PID: 1234})

	_, events, stats := f.Snapshot(10, 10)
	if len(events) != 0 {
		t.Errorf("expected no events after PushEvent on stub, got %d", len(events))
	}
	if stats.TotalEvents != 0 {
		t.Errorf("expected TotalEvents=0, got %d", stats.TotalEvents)
	}
}

func TestSnapshotReturnsEmptyZeroValue(t *testing.T) {
	f := NewFeed()
	alerts, events, stats := f.Snapshot(5, 5)

	if alerts != nil {
		t.Errorf("expected nil alerts, got %v", alerts)
	}
	if events != nil {
		t.Errorf("expected nil events, got %v", events)
	}
	if stats.TotalEvents != 0 || stats.TotalAlerts != 0 || stats.Critical != 0 || stats.Warning != 0 {
		t.Errorf("expected zero-value counters, got %+v", stats)
	}
	// The maps must be non-nil (constructed in the stub) so callers can range/index safely.
	if stats.RuleHits == nil {
		t.Error("expected non-nil RuleHits map")
	}
	if stats.TopProcesses == nil {
		t.Error("expected non-nil TopProcesses map")
	}
	if len(stats.RuleHits) != 0 {
		t.Errorf("expected empty RuleHits, got %d entries", len(stats.RuleHits))
	}
	if len(stats.TopProcesses) != 0 {
		t.Errorf("expected empty TopProcesses, got %d entries", len(stats.TopProcesses))
	}
	if !stats.UpdatedAt.IsZero() {
		t.Errorf("expected zero UpdatedAt, got %v", stats.UpdatedAt)
	}
}

func TestSnapshotMapsAreWritable(t *testing.T) {
	f := NewFeed()
	_, _, stats := f.Snapshot(0, 0)
	// Non-nil maps must be safe to write to.
	stats.RuleHits["x"] = 1
	stats.TopProcesses["bash"] = 2
	if stats.RuleHits["x"] != 1 || stats.TopProcesses["bash"] != 2 {
		t.Error("stub Snapshot maps should be writable")
	}
}

func TestRunReturnsNotCompiledError(t *testing.T) {
	err := Run(context.Background(), NewFeed())
	if err == nil {
		t.Fatal("expected error from stub Run, got nil")
	}
}

func TestRunWizardReturnsNotCompiledError(t *testing.T) {
	out, err := RunWizard()
	if err == nil {
		t.Fatal("expected error from stub RunWizard, got nil")
	}
	if out != "" {
		t.Errorf("expected empty output string, got %q", out)
	}
}

func TestRunFleetReturnsNotCompiledError(t *testing.T) {
	err := RunFleet(context.Background(), NewFeed(), FleetConfig{})
	if err == nil {
		t.Fatal("expected error from stub RunFleet, got nil")
	}
}
