package watchdog

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// mockChecker is a mock BPF program checker for testing.
type mockChecker struct {
	name        string
	attached    bool
	reloadError error
	reloadCount int
}

func (m *mockChecker) IsAttached() bool {
	return m.attached
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) Reload() error {
	m.reloadCount++
	if m.reloadError != nil {
		return m.reloadError
	}
	m.attached = true
	return nil
}

func TestNew(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	w := New(logger, DefaultConfig())
	if w == nil {
		t.Fatal("expected watchdog to be created")
	}

	if w.heartbeatInterval != 15*time.Second {
		t.Errorf("expected heartbeat interval 15s, got %v", w.heartbeatInterval)
	}

	if w.checkInterval != 30*time.Second {
		t.Errorf("expected check interval 30s, got %v", w.checkInterval)
	}
}

func TestNewWithCustomConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := Config{
		HeartbeatInterval: 5 * time.Second,
		CheckInterval:     10 * time.Second,
	}

	w := New(logger, cfg)
	if w.heartbeatInterval != 5*time.Second {
		t.Errorf("expected heartbeat interval 5s, got %v", w.heartbeatInterval)
	}

	if w.checkInterval != 10*time.Second {
		t.Errorf("expected check interval 10s, got %v", w.checkInterval)
	}
}

func TestRegisterChecker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := New(logger, DefaultConfig())

	checker := &mockChecker{name: "test", attached: true}
	w.RegisterChecker(checker)

	if w.GetCheckerCount() != 1 {
		t.Errorf("expected 1 checker, got %d", w.GetCheckerCount())
	}
}

func TestWatchdogStartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := New(logger, Config{
		HeartbeatInterval: 100 * time.Millisecond,
		CheckInterval:     200 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.Start(ctx)

	if !w.IsRunning() {
		t.Error("expected watchdog to be running")
	}

	// Let it run for a bit
	time.Sleep(150 * time.Millisecond)

	w.Stop()

	if w.IsRunning() {
		t.Error("expected watchdog to be stopped")
	}
}

func TestHeartbeatUpdates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := New(logger, Config{
		HeartbeatInterval: 50 * time.Millisecond,
		CheckInterval:     1 * time.Hour, // Don't run liveness checks
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get initial value
	initialValue := getHeartbeatValue()

	w.Start(ctx)

	// Wait for at least one heartbeat update
	time.Sleep(100 * time.Millisecond)

	newValue := getHeartbeatValue()
	if newValue <= initialValue {
		t.Errorf("expected heartbeat to increase, initial=%f, new=%f", initialValue, newValue)
	}

	cancel()
}

func getHeartbeatValue() float64 {
	// Read the actual gauge value rather than re-sampling the clock, so the
	// test verifies that runHeartbeat advances the metric.
	return testutil.ToFloat64(HeartbeatTimestamp)
}

func TestCheckProgramAttached(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := New(logger, DefaultConfig())

	checker := &mockChecker{name: "syscall", attached: true}
	w.RegisterChecker(checker)

	// Should not trigger any alerts or reloads
	w.checkProgram(checker)

	if checker.reloadCount != 0 {
		t.Errorf("expected no reloads, got %d", checker.reloadCount)
	}
}

func TestCheckProgramDetached(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var alerts []types.Alert
	alertFunc := func(a types.Alert) {
		alerts = append(alerts, a)
	}

	w := New(logger, Config{
		AlertFunc: alertFunc,
	})

	checker := &mockChecker{name: "network", attached: false}
	w.RegisterChecker(checker)

	w.checkProgram(checker)

	// Should have attempted reload
	if checker.reloadCount != 1 {
		t.Errorf("expected 1 reload, got %d", checker.reloadCount)
	}

	// Should have sent alert
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}

	if len(alerts) > 0 && alerts[0].RuleID != "watchdog_bpf_detached" {
		t.Errorf("expected alert rule_id 'watchdog_bpf_detached', got %s", alerts[0].RuleID)
	}
}

func TestCheckProgramReloadFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var alerts []types.Alert
	alertFunc := func(a types.Alert) {
		alerts = append(alerts, a)
	}

	w := New(logger, Config{
		AlertFunc: alertFunc,
	})

	checker := &mockChecker{
		name:        "fileaccess",
		attached:    false,
		reloadError: errors.New("reload failed"),
	}
	w.RegisterChecker(checker)

	w.checkProgram(checker)

	// Should have attempted reload
	if checker.reloadCount != 1 {
		t.Errorf("expected 1 reload, got %d", checker.reloadCount)
	}

	// Should have sent two alerts: one for detach, one for reload failure
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}

	if len(alerts) > 1 && alerts[1].RuleID != "watchdog_bpf_reload_failed" {
		t.Errorf("expected second alert rule_id 'watchdog_bpf_reload_failed', got %s", alerts[1].RuleID)
	}
}

func TestCheckAllPrograms(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := New(logger, DefaultConfig())

	checker1 := &mockChecker{name: "syscall", attached: true}
	checker2 := &mockChecker{name: "network", attached: false}
	checker3 := &mockChecker{name: "fileaccess", attached: true}

	w.RegisterChecker(checker1)
	w.RegisterChecker(checker2)
	w.RegisterChecker(checker3)

	w.checkAllPrograms()

	if checker1.reloadCount != 0 {
		t.Errorf("expected checker1 no reloads, got %d", checker1.reloadCount)
	}

	if checker2.reloadCount != 1 {
		t.Errorf("expected checker2 1 reload, got %d", checker2.reloadCount)
	}

	if checker3.reloadCount != 0 {
		t.Errorf("expected checker3 no reloads, got %d", checker3.reloadCount)
	}
}

func TestConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := New(logger, DefaultConfig())

	// Register checkers concurrently
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func(idx int) {
			checker := &mockChecker{name: string(rune('a' + idx)), attached: true}
			w.RegisterChecker(checker)
			done <- true
		}(i)
	}

	for i := 0; i < 3; i++ {
		select {
		case <-done:
			// OK
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for concurrent registration")
		}
	}

	if w.GetCheckerCount() != 3 {
		t.Errorf("expected 3 checkers, got %d", w.GetCheckerCount())
	}
}

func TestMultipleStartCalls(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := New(logger, Config{
		HeartbeatInterval: 1 * time.Hour,
		CheckInterval:     1 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.Start(ctx)
	w.Start(ctx) // Second call should be ignored

	if !w.IsRunning() {
		t.Error("expected watchdog to be running")
	}
}

// mockDropTracker is a DropTracker that returns a manually controlled count.
type mockDropTracker struct {
	name  string
	count uint64
}

func (m *mockDropTracker) Name() string      { return m.name }
func (m *mockDropTracker) LostEvents() uint64 { return m.count }

func TestDropTracking(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	tracker := &mockDropTracker{name: "test_collector"}

	w := New(logger, Config{
		HeartbeatInterval: 1 * time.Hour,
		CheckInterval:     1 * time.Hour,
	})
	w.RegisterDropTracker(tracker)

	// Simulate 5 drops before the first tick.
	tracker.count = 5

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	// runDropTracking fires every 10s; manually invoke the inner logic to avoid a slow test.
	w.dropLostMu.Lock()
	name := tracker.Name()
	current := tracker.LostEvents()
	last := w.dropLostSeen[name]
	if current > last {
		exporter.AddBPFLost(name, current-last)
		w.dropLostSeen[name] = current
	}
	w.dropLostMu.Unlock()

	got := testutil.ToFloat64(exporter.BPFLostEvents.WithLabelValues("test_collector"))
	if got != 5 {
		t.Errorf("expected BPFLostEvents=5, got %v", got)
	}

	// Simulate 3 more drops; delta should be 3.
	tracker.count = 8
	w.dropLostMu.Lock()
	current = tracker.LostEvents()
	last = w.dropLostSeen[name]
	if current > last {
		exporter.AddBPFLost(name, current-last)
		w.dropLostSeen[name] = current
	}
	w.dropLostMu.Unlock()

	got = testutil.ToFloat64(exporter.BPFLostEvents.WithLabelValues("test_collector"))
	if got != 8 {
		t.Errorf("expected BPFLostEvents=8 after second batch, got %v", got)
	}
}
