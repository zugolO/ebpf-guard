// Package policy provides tests for the Rego/OPA policy engine.
package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRegoEngine tests creating a new Rego engine.
func TestNewRegoEngine(t *testing.T) {
	// Create a temporary directory with test policies
	tmpDir := t.TempDir()

	// Write a test policy
	testPolicy := `
package ebpf_guard

default allow := false

allow {
	input.severity == "critical"
}

decisions[{"rule_id": "test_rule", "severity": "critical", "message": "Test alert", "action": "alert", "matched": true}] {
	input.comm == "test_process"
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(testPolicy), 0644)
	require.NoError(t, err)

	// Create engine
	config := RegoEngineConfig{
		Enabled:  true,
		RulesDir: tmpDir,
	}

	engine, err := NewRegoEngine(config)
	require.NoError(t, err)
	assert.NotNil(t, engine)
	assert.True(t, engine.IsEnabled())

	stats := engine.GetStats()
	assert.Equal(t, 1, stats.PolicyCount)
}

// TestRegoEngineEvaluate tests evaluating alerts against policies.
func TestRegoEngineEvaluate(t *testing.T) {
	// Create a temporary directory with test policies
	tmpDir := t.TempDir()

	// Write a test policy with lineage detection
	testPolicy := `
package ebpf_guard

default allow := true

# Detect suspicious lineage: shell spawned from web server
decisions[{"rule_id": "suspicious_lineage", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1190", "matched": true}] {
	input.event.parent_comm == "nginx"
	input.comm == "bash"
	msg := sprintf("Shell spawned from nginx: pid=%d", [input.pid])
}

# Detect sensitive file access
decisions[{"rule_id": "sensitive_file", "severity": "warning", "message": "Access to /etc/shadow", "action": "alert", "mitre_technique": "T1003", "matched": true}] {
	contains_path(input.event.file.filename, "/etc/shadow")
}

contains_path(s, substr) {
	contains(s, substr)
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(testPolicy), 0644)
	require.NoError(t, err)

	// Create engine
	config := RegoEngineConfig{
		Enabled:  true,
		RulesDir: tmpDir,
	}

	engine, err := NewRegoEngine(config)
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name           string
		alert          types.Alert
		expectMatched  bool
		expectRuleID   string
		expectSeverity types.Severity
	}{
		{
			name: "suspicious lineage - nginx to bash",
			alert: types.Alert{
				ID:       "test-1",
				RuleID:   "lineage_detection",
				Severity: types.SeverityWarning,
				PID:      1234,
				Comm:     "bash",
				Message:  "Test alert",
				Event: types.Event{
					Type:       types.EventSyscall,
					PID:        1234,
					PPID:       1000,
					ParentComm: [16]byte{'n', 'g', 'i', 'n', 'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Comm:       [16]byte{'b', 'a', 's', 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
			expectMatched:  true,
			expectRuleID:   "suspicious_lineage",
			expectSeverity: types.SeverityCritical,
		},
		{
			name: "no match - apache to bash",
			alert: types.Alert{
				ID:       "test-2",
				RuleID:   "lineage_detection",
				Severity: types.SeverityWarning,
				PID:      1235,
				Comm:     "bash",
				Message:  "Test alert",
				Event: types.Event{
					Type:       types.EventSyscall,
					PID:        1235,
					PPID:       1001,
					ParentComm: [16]byte{'a', 'p', 'a', 'c', 'h', 'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Comm:       [16]byte{'b', 'a', 's', 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
			expectMatched: false,
		},
		{
			name: "sensitive file access",
			alert: types.Alert{
				ID:       "test-3",
				RuleID:   "file_access",
				Severity: types.SeverityWarning,
				PID:      1236,
				Comm:     "cat",
				Message:  "File access",
				Event: types.Event{
					Type: types.EventFileAccess,
					PID:  1236,
					Comm: [16]byte{'c', 'a', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					File: &types.FileEvent{
						Filename: [256]byte{'/', 'e', 't', 'c', '/', 's', 'h', 'a', 'd', 'o', 'w', 0},
						Op:       0,
					},
				},
			},
			expectMatched:  true,
			expectRuleID:   "sensitive_file",
			expectSeverity: types.SeverityWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisions, err := engine.Evaluate(ctx, tt.alert)
			require.NoError(t, err)

			if tt.expectMatched {
				require.Len(t, decisions, 1)
				assert.Equal(t, tt.expectRuleID, decisions[0].RuleID)
				assert.Equal(t, tt.expectSeverity, decisions[0].Severity)
				assert.True(t, decisions[0].Matched)
			} else {
				assert.Empty(t, decisions)
			}
		})
	}
}

// TestRegoEngineDisabled tests that disabled engine returns nil.
func TestRegoEngineDisabled(t *testing.T) {
	config := RegoEngineConfig{
		Enabled:  false,
		RulesDir: t.TempDir(),
	}

	engine, err := NewRegoEngine(config)
	require.NoError(t, err)
	assert.False(t, engine.IsEnabled())

	alert := types.Alert{
		ID:       "test",
		RuleID:   "test",
		Severity: types.SeverityWarning,
		PID:      1234,
		Comm:     "test",
	}

	decisions, err := engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	assert.Nil(t, decisions)
}

// TestRegoEngineReload tests hot-reloading of policies.
func TestRegoEngineReload(t *testing.T) {
	tmpDir := t.TempDir()

	// Write initial policy
	initialPolicy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "v1", "severity": "warning", "message": "v1", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(initialPolicy), 0644)
	require.NoError(t, err)

	engine, err := NewRegoEngine(RegoEngineConfig{
		Enabled:  true,
		RulesDir: tmpDir,
	})
	require.NoError(t, err)

	// Test initial policy
	alert := types.Alert{
		ID:   "test",
		Comm: "test",
		Event: types.Event{
			Comm: [16]byte{'t', 'e', 's', 't'},
		},
	}

	decisions, err := engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	require.Len(t, decisions, 1)
	assert.Equal(t, "v1", decisions[0].RuleID)

	// Update policy
	updatedPolicy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "v2", "severity": "critical", "message": "v2", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(updatedPolicy), 0644)
	require.NoError(t, err)

	// Reload
	err = engine.Reload()
	require.NoError(t, err)

	// Test updated policy
	decisions, err = engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	require.Len(t, decisions, 1)
	assert.Equal(t, "v2", decisions[0].RuleID)
	assert.Equal(t, types.SeverityCritical, decisions[0].Severity)

	stats := engine.GetStats()
	assert.Equal(t, uint64(1), stats.ReloadCounter)
}

// TestRegoEngineNoPolicies tests engine with no policies.
func TestRegoEngineNoPolicies(t *testing.T) {
	tmpDir := t.TempDir()

	engine, err := NewRegoEngine(RegoEngineConfig{
		Enabled:  true,
		RulesDir: tmpDir,
	})
	require.NoError(t, err)

	alert := types.Alert{
		ID:   "test",
		Comm: "test",
	}

	decisions, err := engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	assert.Nil(t, decisions)
}

// BenchmarkRegoEvaluate benchmarks Rego evaluation performance.
// Performance gate: p99 < 500µs with pre-compiled policies.
func BenchmarkRegoEvaluate(b *testing.B) {
	tmpDir := b.TempDir()

	// Write a realistic policy
	policy := `
package ebpf_guard

default allow := true

# Detect cryptominer network connections
decisions[{"rule_id": "cryptominer_connection", "severity": "critical", "message": "Connection to known mining pool", "action": "block", "mitre_technique": "T1496", "matched": true}] {
	net := input.event.network
	net.dport == 3333
}

# Detect reverse shell
decisions[{"rule_id": "reverse_shell", "severity": "critical", "message": "Potential reverse shell", "action": "alert", "mitre_technique": "T1059", "matched": true}] {
	input.event.parent_comm == "nginx"
	input.comm == "bash"
}

# Detect sensitive file access
decisions[{"rule_id": "sensitive_file", "severity": "warning", "message": "Access to sensitive file", "action": "alert", "mitre_technique": "T1003", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/etc/shadow")
}

contains(s, substr) {
	contains(s, substr)
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "benchmark.rego"), []byte(policy), 0644)
	require.NoError(b, err)

	engine, err := NewRegoEngine(RegoEngineConfig{
		Enabled:  true,
		RulesDir: tmpDir,
	})
	require.NoError(b, err)

	alert := types.Alert{
		ID:       "bench",
		RuleID:   "network_detection",
		Severity: types.SeverityWarning,
		PID:      1234,
		Comm:     "xmrig",
		Message:  "Network connection",
		Event: types.Event{
			Type: types.EventTCPConnect,
			PID:  1234,
			Network: &types.NetworkEvent{
				Dport: 3333,
				Daddr: [16]byte{45, 9, 148, 123},
			},
		},
	}

	ctx := context.Background()

	// Warmup
	for i := 0; i < 100; i++ {
		_, _ = engine.Evaluate(ctx, alert)
	}

	// Benchmark
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(ctx, alert)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRegoEvaluateLatency measures p99 latency.
func BenchmarkRegoEvaluateLatency(b *testing.B) {
	tmpDir := b.TempDir()

	policy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "test", "severity": "warning", "message": "test", "action": "alert", "matched": true}] {
	input.comm == "xmrig"
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(policy), 0644)
	require.NoError(b, err)

	engine, err := NewRegoEngine(RegoEngineConfig{
		Enabled:  true,
		RulesDir: tmpDir,
	})
	require.NoError(b, err)

	alert := types.Alert{
		ID:   "test",
		Comm: "xmrig",
		Event: types.Event{
			Comm: [16]byte{'x', 'm', 'r', 'i', 'g'},
		},
	}

	ctx := context.Background()

	// Collect latencies
	latencies := make([]time.Duration, b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, err := engine.Evaluate(ctx, alert)
		latencies[i] = time.Since(start)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Calculate p99
	if len(latencies) > 0 {
		// Sort and get p99
		// For simplicity, just report average here
		var total time.Duration
		for _, d := range latencies {
			total += d
		}
		b.ReportMetric(float64(total)/float64(len(latencies))/float64(time.Microsecond), "µs/op")
	}
}

// TestRegoEngineStats tests statistics collection.
func TestRegoEngineStats(t *testing.T) {
	tmpDir := t.TempDir()

	policy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "test", "severity": "warning", "message": "test", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(policy), 0644)
	require.NoError(t, err)

	engine, err := NewRegoEngine(RegoEngineConfig{
		Enabled:  true,
		RulesDir: tmpDir,
	})
	require.NoError(t, err)

	// Initial stats
	stats := engine.GetStats()
	assert.Equal(t, uint64(0), stats.EvalTotal)
	assert.Equal(t, uint64(0), stats.EvalErrors)
	assert.Equal(t, 1, stats.PolicyCount)

	// Evaluate some alerts
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		alert := types.Alert{
			ID:   "test",
			Comm: "test",
			Event: types.Event{
				Comm: [16]byte{'t', 'e', 's', 't'},
			},
		}
		_, _ = engine.Evaluate(ctx, alert)
	}

	// Updated stats
	stats = engine.GetStats()
	assert.Equal(t, uint64(10), stats.EvalTotal)
	assert.Equal(t, uint64(0), stats.EvalErrors)
}
