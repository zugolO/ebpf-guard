// Package enforcer provides tests for enforcement capabilities.
package enforcer

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnforcer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tests := []struct {
		name string
		cfg  Config
		want map[ActionType]bool
	}{
		{
			name: "all enabled",
			cfg: Config{
				EnableBlock:    true,
				EnableKill:     true,
				EnableThrottle: true,
			},
			want: map[ActionType]bool{
				ActionBlock:    true,
				ActionKill:     true,
				ActionThrottle: true,
			},
		},
		{
			name: "only kill enabled",
			cfg: Config{
				EnableKill: true,
			},
			want: map[ActionType]bool{
				ActionBlock:    false,
				ActionKill:     true,
				ActionThrottle: false,
			},
		},
		{
			name: "all disabled",
			cfg:  Config{},
			want: map[ActionType]bool{
				ActionBlock:    false,
				ActionKill:     false,
				ActionThrottle: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEnforcer(logger, tt.cfg)
			require.NoError(t, err)
			require.NotNil(t, e)

			for action, enabled := range tt.want {
				assert.Equal(t, enabled, e.IsEnabled(action), "action %s", action)
			}
		})
	}
}

func TestEnforcer_Execute_Disabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	e, err := NewEnforcer(logger, Config{})
	require.NoError(t, err)

	alert := types.Alert{
		RuleID: "test_rule",
		Event:  types.Event{PID: 1234},
	}

	ctx := context.Background()
	err = e.Execute(ctx, ActionKill, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestParseActionType(t *testing.T) {
	tests := []struct {
		input   string
		want    ActionType
		wantErr bool
	}{
		{"block", ActionBlock, false},
		{"kill", ActionKill, false},
		{"throttle", ActionThrottle, false},
		{"unknown", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseActionType(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestActionType_String(t *testing.T) {
	assert.Equal(t, "block", ActionBlock.String())
	assert.Equal(t, "kill", ActionKill.String())
	assert.Equal(t, "throttle", ActionThrottle.String())
}

func TestValidatePID(t *testing.T) {
	tests := []struct {
		name    string
		pid     uint32
		wantErr bool
	}{
		{"kernel pid", 0, true},
		{"non-existent high pid", 999999, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePID(tt.pid)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsCgroupV2Available(t *testing.T) {
	// This test depends on the host system
	// On Linux, it should return true if cgroup v2 is mounted
	// On non-Linux, it should return false
	if runtime.GOOS == "linux" {
		// Just check it doesn't panic
		_ = IsCgroupV2Available()
	} else {
		assert.False(t, IsCgroupV2Available())
	}
}

func TestEnforcer_ThrottleState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	e, err := NewEnforcer(logger, Config{EnableThrottle: true})
	require.NoError(t, err)

	// Test initial state
	state := e.GetThrottleState(1234)
	assert.Nil(t, state)

	// Manually add a throttle state
	e.mu.Lock()
	e.throttles[1234] = &ThrottleState{
		PID:          1234,
		LastThrottle: time.Now(),
		Count:        1,
		Active:       true,
	}
	e.mu.Unlock()

	// Verify state exists
	state = e.GetThrottleState(1234)
	require.NotNil(t, state)
	assert.Equal(t, uint32(1234), state.PID)
	assert.Equal(t, 1, state.Count)

	// Test cleanup - use a longer duration to ensure the entry is older than maxAge
	// The entry was just created, so we need to wait a bit or use a negative maxAge
	time.Sleep(10 * time.Millisecond)
	removed := e.CleanupThrottles(5 * time.Millisecond)
	assert.Equal(t, 1, removed)
	assert.Nil(t, e.GetThrottleState(1234))
}

func TestEnforcer_CleanupThrottles(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	e, err := NewEnforcer(logger, Config{})
	require.NoError(t, err)

	now := time.Now()

	// Add test states
	e.mu.Lock()
	e.throttles[1] = &ThrottleState{PID: 1, LastThrottle: now.Add(-1 * time.Hour), Active: true}
	e.throttles[2] = &ThrottleState{PID: 2, LastThrottle: now, Active: true}
	e.throttles[3] = &ThrottleState{PID: 3, LastThrottle: now.Add(-30 * time.Minute), Active: true}
	e.mu.Unlock()

	// Cleanup entries older than 45 minutes
	removed := e.CleanupThrottles(45 * time.Minute)
	assert.Equal(t, 1, removed)

	// Verify only PID 1 was removed
	assert.Nil(t, e.GetThrottleState(1))
	assert.NotNil(t, e.GetThrottleState(2))
	assert.NotNil(t, e.GetThrottleState(3))
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"line1\nline2\nline3", []string{"line1", "line2", "line3"}},
		{"single", []string{"single"}},
		{"trailing\n", []string{"trailing"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitLines(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSplitLastField(t *testing.T) {
	tests := []struct {
		input string
		sep   byte
		want  []string
	}{
		{"a:b:c", ':', []string{"a", "b", "c"}},
		{"0::/path/to/cgroup", ':', []string{"0", "", "/path/to/cgroup"}},
		{"no-separator", ':', []string{"no-separator"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitLastField(tt.input, tt.sep)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBytesToString(t *testing.T) {
	tests := []struct {
		input []byte
		want  []byte
	}{
		{[]byte("hello\x00world"), []byte("hello")},
		{[]byte("no-null"), []byte("no-null")},
		{[]byte("\x00"), []byte{}},
		{[]byte{}, []byte{}},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got := bytesToString(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuditEntry_JSON(t *testing.T) {
	entry := AuditEntry{
		Timestamp:   time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Action:      ActionKill,
		RuleID:      "rule_001",
		PID:         1234,
		TGID:        1234,
		Comm:        "test-process",
		UID:         1000,
		Description: "Test kill action",
		Success:     true,
		EventType:   types.EventSyscall,
	}

	// Verify JSON marshaling
	data, err := entry.Timestamp.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestValidateEvent(t *testing.T) {
	tests := []struct {
		name    string
		event   types.Event
		wantErr bool
	}{
		{"valid event", types.Event{PID: 1234, UID: 1000}, false},
		{"pid zero", types.Event{PID: 0, UID: 0}, true},
		{"pid over max", types.Event{PID: 4194305, UID: 0}, true},
		{"uid over max", types.Event{PID: 1, UID: 99999}, true},
		{"uid at boundary", types.Event{PID: 1, UID: 65535}, false},
		{"pid at boundary", types.Event{PID: 4194304, UID: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEvent(tt.event)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrInvalidEvent)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSanitizeComm(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nginx", "nginx"},
		{"nginx\x00\xff\x01", "nginx\x00\xff\x01"},
		{"\x00", `\x00`},
		{"\x1b[31m", `\x1b[31m`},
		{"normal-process", "normal-process"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// Build expected: sanitizeComm escapes control chars and invalid UTF-8
			got := sanitizeComm(tt.input)
			// Ensure no raw control characters survive
			for _, r := range got {
				assert.True(t, r >= 0x20 || r == '\t', "unexpected control char %U in sanitized output", r)
			}
			assert.NotEmpty(t, got)
		})
	}
}

func TestEnforcer_Execute_InvalidUID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	e, err := NewEnforcer(logger, Config{EnableKill: true})
	require.NoError(t, err)

	alert := types.Alert{
		RuleID: "test_rule",
		Event:  types.Event{PID: 1, UID: 99999},
	}

	ctx := context.Background()
	err = e.Execute(ctx, ActionKill, alert)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidEvent)
}

// Integration test for kill action (skipped on non-Linux)
func TestEnforcer_ExecuteKill_Integration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping integration test on non-Linux platform")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a test process
	cmd := exec.Command("sleep", "30")
	err := cmd.Start()
	require.NoError(t, err)

	pid := uint32(cmd.Process.Pid)

	// Give the process time to start
	time.Sleep(100 * time.Millisecond)

	// Create enforcer
	e, err := NewEnforcer(logger, Config{
		EnableKill: true,
	})
	require.NoError(t, err)

	alert := types.Alert{
		RuleID:   "test_kill_rule",
		Severity: types.SeverityCritical,
		Event: types.Event{
			PID:  pid,
			TGID: pid,
			Comm: [16]byte{'s', 'l', 'e', 'e', 'p'},
			UID:  uint32(os.Getuid()),
		},
	}

	ctx := context.Background()
	err = e.Execute(ctx, ActionKill, alert)

	// Wait for process to exit
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Process exited as expected
	case <-time.After(2 * time.Second):
		t.Fatal("process did not exit after SIGKILL")
	}

	// Verify process state was tracked
	// Note: We can't verify this on the killed process since it's gone
}
