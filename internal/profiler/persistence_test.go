package profiler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestSaveAndLoadState_RoundTrip(t *testing.T) {
	ctx := context.Background()
	learningPeriod := 100 * time.Millisecond
	ad := NewAnomalyDetectorWithContext(ctx, 0.8, learningPeriod, 0.3)

	// Force learning complete by backdating startTime and setting sample count.
	ad.learner.mu.Lock()
	ad.learner.startTime = time.Now().Add(-2 * learningPeriod)
	ad.learner.sampleCount = 200
	ad.learner.mu.Unlock()

	// ProcessEvent calls IsLearningComplete which will flip the atomic flag.
	e := types.Event{Type: types.EventSyscall, PID: 42, Syscall: &types.SyscallEvent{Nr: 1}}
	for i := 0; i < 5; i++ {
		ad.ProcessEvent(e, false)
	}
	if !ad.IsLearningComplete() {
		t.Fatal("expected learning to be complete before save")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := ad.SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	// Restore into a fresh detector.
	ad2 := NewAnomalyDetectorWithContext(ctx, 0.8, learningPeriod, 0.3)
	if ad2.IsLearningComplete() {
		t.Fatal("fresh detector must not start in completed state")
	}
	restored, err := ad2.LoadState(path, learningPeriod)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !restored {
		t.Fatal("expected restored=true since learning was complete at save time")
	}
	if !ad2.IsLearningComplete() {
		t.Fatal("detector should be in completed state after load")
	}
}

func TestLoadState_StaleStateIgnored(t *testing.T) {
	ctx := context.Background()
	learningPeriod := 50 * time.Millisecond
	ad := NewAnomalyDetectorWithContext(ctx, 0.8, learningPeriod, 0.3)

	ad.learner.mu.Lock()
	ad.learner.learningComplete = true
	ad.learner.mu.Unlock()
	ad.learningComplete.Store(true)

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := ad.SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Patch SavedAt to be ancient.
	data, _ := os.ReadFile(path)
	var state ProfilerState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal for patch: %v", err)
	}
	state.SavedAt = time.Now().Add(-10 * time.Hour)
	patched, _ := json.Marshal(state)
	_ = os.WriteFile(path, patched, 0600)

	ad2 := NewAnomalyDetectorWithContext(ctx, 0.8, learningPeriod, 0.3)
	restored, err := ad2.LoadState(path, learningPeriod)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if restored {
		t.Error("stale state must not be restored")
	}
	if ad2.IsLearningComplete() {
		t.Error("fresh detector must not have learning complete after stale load")
	}
}

func TestLoadState_MissingFile(t *testing.T) {
	ctx := context.Background()
	ad := NewAnomalyDetectorWithContext(ctx, 0.8, time.Minute, 0.3)
	restored, err := ad.LoadState("/nonexistent/path/state.json", time.Minute)
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if restored {
		t.Error("missing file should return restored=false")
	}
}

func TestSaveState_ProfilesRoundTrip(t *testing.T) {
	ctx := context.Background()
	learningPeriod := 50 * time.Millisecond
	ad := NewAnomalyDetectorWithContext(ctx, 0.8, learningPeriod, 0.3)

	// Force learning complete.
	ad.learner.mu.Lock()
	ad.learner.startTime = time.Now().Add(-2 * learningPeriod)
	ad.learner.sampleCount = 200
	ad.learner.learningComplete = true
	ad.learner.mu.Unlock()
	ad.learningComplete.Store(true)

	// Record a network event to create a workload profile.
	netEvent := types.Event{
		Type: types.EventTCPConnect,
		PID:  1,
		Network: &types.NetworkEvent{Dport: 443, Family: 2},
	}
	ad.ProcessEvent(netEvent, false)

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := ad.SaveState(path); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	ad2 := NewAnomalyDetectorWithContext(ctx, 0.8, learningPeriod, 0.3)
	restored, err := ad2.LoadState(path, learningPeriod)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !restored {
		t.Fatal("expected restored=true")
	}

	// Verify the port 443 EWMA was restored.
	key := WorkloadKeyFromEvent(netEvent)
	p := ad2.profileManager.GetByKey(key)
	if p == nil {
		t.Fatal("workload profile not restored")
	}
	p.mu.Lock()
	_, hasPort := p.NetworkProfile.DestPorts[443]
	p.mu.Unlock()
	if !hasPort {
		t.Error("port 443 EWMA not restored in network profile")
	}
}
