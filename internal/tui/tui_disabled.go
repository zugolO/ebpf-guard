//go:build !tui

// Package tui provides a stub when the tui build tag is not set.
package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Feed is a stub alert/event feed that discards all data.
type Feed struct{}

// NewFeed creates a stub Feed that discards all events and alerts.
func NewFeed() *Feed { return &Feed{} }

// PushAlert is a no-op in the stub.
func (f *Feed) PushAlert(_ types.Alert) {}

// PushEvent is a no-op in the stub.
func (f *Feed) PushEvent(_ types.Event) {}

// DashboardStats is a stub type needed for the Snapshot return signature.
type DashboardStats struct {
	TotalEvents  int64
	TotalAlerts  int64
	Critical     int64
	Warning      int64
	RuleHits     map[string]int64
	TopProcesses map[string]int64
	UpdatedAt    time.Time
}

// Snapshot returns empty stub data.
func (f *Feed) Snapshot(_, _ int) ([]types.Alert, []types.Event, DashboardStats) {
	return nil, nil, DashboardStats{
		RuleHits:     make(map[string]int64),
		TopProcesses: make(map[string]int64),
	}
}

// Run is a stub that returns an error indicating TUI is not compiled in.
// Use -tags tui to build with the interactive terminal dashboard.
func Run(_ context.Context, _ *Feed) error {
	return fmt.Errorf("tui: interactive dashboard not compiled in — build with -tags tui")
}

// RunWizard is a stub that returns an error indicating TUI is not compiled in.
// Use -tags tui to build with the interactive rule builder wizard.
func RunWizard() (string, error) {
	return "", fmt.Errorf("tui: interactive wizard not compiled in — build with -tags tui")
}

// RunFleet is a stub that returns an error indicating TUI is not compiled in.
// Use -tags tui to build with the fleet-mode dashboard (`dashboard --fleet`).
func RunFleet(_ context.Context, _ *Feed, _ FleetConfig) error {
	return fmt.Errorf("tui: fleet dashboard not compiled in — build with -tags tui")
}
