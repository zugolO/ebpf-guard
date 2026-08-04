package canary

import (
	"os"
	"strconv"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestCanarySelfPIDException verifies that canary rules include an exception
// for the agent's own PID to prevent false positives when the agent verifies
// its own canary files (P1-17).
func TestCanarySelfPIDException(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AlertSeverity: "critical",
		Files:         []string{"/etc/shadow.canary", "/tmp/.secret_key"},
	}
	mgr := New(cfg)
	rules := mgr.Rules()

	selfPIDStr := strconv.FormatUint(uint64(mgr.selfPID), 10)

	for i, rule := range rules {
		t.Run(rule.ID, func(t *testing.T) {
			if len(rule.Exceptions) != 1 {
				t.Fatalf("expected 1 exception, got %d for rule %s", len(rule.Exceptions), rule.ID)
			}
			exc := rule.Exceptions[0]
			if exc.Name != "ebpf-guard-self" {
				t.Errorf("expected exception name 'ebpf-guard-self', got '%s'", exc.Name)
			}
			if exc.Condition.Field != "pid" {
				t.Errorf("expected exception field 'pid', got '%s'", exc.Condition.Field)
			}
			if exc.Condition.Op != correlator.OpEquals {
				t.Errorf("expected exception op 'equals', got '%s'", exc.Condition.Op)
			}
			if len(exc.Condition.Values) != 1 {
				t.Fatalf("expected 1 exception value, got %d", len(exc.Condition.Values))
			}
			if exc.Condition.Values[0] != selfPIDStr {
				t.Errorf("expected exception value '%s' (current PID), got '%s'", selfPIDStr, exc.Condition.Values[0])
			}
			_ = i
		})
	}
}

// TestCanaryManagerCapturesSelfPID verifies that the Manager captures
// the agent's PID at initialization time (P1-17).
func TestCanaryManagerCapturesSelfPID(t *testing.T) {
	cfg := Config{
		Enabled: true,
	}
	mgr := New(cfg)

	expectedPID := uint32(os.Getpid())
	if mgr.selfPID != expectedPID {
		t.Errorf("expected selfPID %d, got %d", expectedPID, mgr.selfPID)
	}
}

// TestCanaryRuleValidatesPIDField verifies that the "pid" field is valid
// for file event rules (P1-17 requires extending the field validation).
func TestCanaryRuleValidatesPIDField(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AlertSeverity: "critical",
		Files:         []string{"/tmp/test.canary"},
	}
	mgr := New(cfg)
	rules := mgr.Rules()

	engine := correlator.NewRuleEngine(rules)
	if engine == nil {
		t.Fatal("NewRuleEngine returned nil engine")
	}
}

// TestCanaryExceptionBlocksSelfPIDEvents verifies that events from the
// agent's own PID are suppressed by the canary rule exception (P1-17).
func TestCanaryExceptionBlocksSelfPIDEvents(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AlertSeverity: "critical",
		Files:         []string{"/tmp/test.canary"},
	}
	mgr := New(cfg)
	rules := mgr.Rules()

	engine := correlator.NewRuleEngine(rules)

	selfPID := mgr.selfPID
	canaryPath := mgr.Paths()[0]

	testEvent := types.Event{
		Type: types.EventFileAccess,
		PID:  selfPID,
		Comm: [16]byte{'e', 'b', 'p', 'f', '-', 'g', 'u', 'a', 'r', 'd'},
		File: &types.FileEvent{
			Filename: [256]byte{},
		},
	}
	copy(testEvent.File.Filename[:], canaryPath)

	alerts := engine.Evaluate(testEvent)
	if len(alerts) > 0 {
		t.Errorf("expected 0 alerts (exception should block), got %d alerts from rule(s): %v",
			len(alerts), alerts)
	}
}
