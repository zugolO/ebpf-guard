//go:build rego

package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestDefaultRegoEngineConfig_Values asserts the exact default configuration
// values returned, independent of any engine construction.
func TestDefaultRegoEngineConfig_Values(t *testing.T) {
	cfg := DefaultRegoEngineConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "rules/rego", cfg.RulesDir)
}

// TestEventTypePartition covers every branch of the event-type-to-partition
// mapping, including the "full" fallback for unmapped event types.
func TestEventTypePartition(t *testing.T) {
	cases := []struct {
		name string
		et   types.EventType
		want string
	}{
		{"syscall", types.EventSyscall, "syscall"},
		{"privesc", types.EventPrivesc, "syscall"},
		{"kmod_load", types.EventKmodLoad, "syscall"},
		{"cgroup_esc", types.EventCgroupEsc, "syscall"},
		{"tcp_connect", types.EventTCPConnect, "network"},
		{"net_close", types.EventNetClose, "network"},
		{"file_access", types.EventFileAccess, "file"},
		{"dns", types.EventDNS, "dns"},
		{"tls_falls_back_to_full", types.EventTLS, "full"},
		{"unmapped_zero_value_falls_back_to_full", types.EventType(0), "full"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eventTypePartition(tc.et)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestEventToInput exercises every populated sub-event branch (syscall via
// top-level fields, network, file, tls, dns) so eventToInput's conditionals
// are all observed.
func TestEventToInput(t *testing.T) {
	t.Run("network event populates network map", func(t *testing.T) {
		ev := types.Event{
			Type: types.EventTCPConnect,
			PID:  111,
			Network: &types.NetworkEvent{
				Saddr:  [16]byte{10, 0, 0, 1},
				Daddr:  [16]byte{10, 0, 0, 2},
				Sport:  1234,
				Dport:  443,
				Proto:  6,
				Family: types.AFInet,
			},
		}
		result := eventToInput(ev)
		net, ok := result["network"].(map[string]interface{})
		require.True(t, ok)
		assert.EqualValues(t, 443, net["dport"])
		assert.EqualValues(t, 1234, net["sport"])
		assert.EqualValues(t, 6, net["proto"])
		assert.EqualValues(t, int(types.AFInet), net["family"])

		// Branches for other sub-events must be absent when unset.
		_, hasFile := result["file"]
		_, hasTLS := result["tls"]
		_, hasDNS := result["dns"]
		assert.False(t, hasFile)
		assert.False(t, hasTLS)
		assert.False(t, hasDNS)
	})

	t.Run("tls event populates tls map and trims data", func(t *testing.T) {
		var data [256]byte
		copy(data[:], "GET / HTTP/1.1")
		ev := types.Event{
			Type: types.EventTLS,
			TLS: &types.TLSEvent{
				Direction: 1,
				DataLen:   14,
				Data:      data,
			},
		}
		result := eventToInput(ev)
		tls, ok := result["tls"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "GET / HTTP/1.1", tls["data"])
		assert.EqualValues(t, 1, tls["direction"])
		assert.EqualValues(t, 14, tls["data_len"])
	})

	t.Run("dns event populates dns map", func(t *testing.T) {
		ev := types.Event{
			Type: types.EventDNS,
			DNS: &types.DNSEvent{
				QName:       "example.com",
				QType:       1,
				RCode:       0,
				Direction:   1,
				ResponseIPs: []string{"1.2.3.4"},
			},
		}
		result := eventToInput(ev)
		dns, ok := result["dns"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "example.com", dns["qname"])
		assert.Equal(t, []string{"1.2.3.4"}, dns["response_ips"])
	})

	t.Run("syscall event populates syscall map", func(t *testing.T) {
		ev := types.Event{
			Type: types.EventSyscall,
			Syscall: &types.SyscallEvent{
				Nr:   59,
				Ret:  0,
				Args: [6]uint64{1, 2, 3, 4, 5, 6},
			},
		}
		result := eventToInput(ev)
		sc, ok := result["syscall"].(map[string]interface{})
		require.True(t, ok)
		assert.EqualValues(t, 59, sc["nr"])
	})

	t.Run("comm and parent_comm are trimmed of trailing nulls", func(t *testing.T) {
		ev := types.Event{
			Comm:       [16]byte{'s', 'h', 0, 0},
			ParentComm: [16]byte{'i', 'n', 'i', 't', 0, 0, 0},
		}
		result := eventToInput(ev)
		assert.Equal(t, "sh", result["comm"])
		assert.Equal(t, "init", result["parent_comm"])
	})
}

// TestTrimNullBytes covers both the "found a null byte" branch and the
// "no null byte present" fall-through branch.
func TestTrimNullBytes(t *testing.T) {
	assert.Equal(t, []byte("abc"), trimNullBytes([]byte{'a', 'b', 'c', 0, 0}))
	// No null byte anywhere in the slice: the loop never returns early and
	// falls through to returning the input unchanged.
	full := []byte{'a', 'b', 'c'}
	assert.Equal(t, full, trimNullBytes(full))
	// Empty slice: loop body never runs, falls through immediately.
	assert.Equal(t, []byte{}, trimNullBytes([]byte{}))
}

// TestSetDurationObserver verifies the observer is actually invoked with a
// non-negative duration on a real Evaluate call, and that clearing it (nil)
// stops further invocations.
func TestSetDurationObserver(t *testing.T) {
	tmpDir := t.TempDir()
	policy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "r1", "severity": "warning", "message": "m", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(policy), 0644))

	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.NoError(t, err)

	var observed time.Duration
	calls := 0
	engine.SetDurationObserver(func(d time.Duration) {
		calls++
		observed = d
	})

	alert := types.Alert{
		Comm: "test",
		Event: types.Event{
			Comm: [16]byte{'t', 'e', 's', 't'},
		},
	}
	_, err = engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)

	assert.Equal(t, 1, calls)
	assert.GreaterOrEqual(t, observed, time.Duration(0))

	// Clearing the observer (nil) must stop further invocations without error.
	engine.SetDurationObserver(nil)
	_, err = engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "observer must not fire once cleared")
}

// TestSetEnabled_TogglesEvaluateBehavior directly exercises SetEnabled and
// observes its effect on both IsEnabled and subsequent Evaluate calls.
func TestSetEnabled_TogglesEvaluateBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	policy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "r1", "severity": "warning", "message": "m", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(policy), 0644))

	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.NoError(t, err)
	require.True(t, engine.IsEnabled())

	alert := types.Alert{
		Comm: "test",
		Event: types.Event{
			Comm: [16]byte{'t', 'e', 's', 't'},
		},
	}

	decisions, err := engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	require.Len(t, decisions, 1)

	engine.SetEnabled(false)
	assert.False(t, engine.IsEnabled())

	decisions, err = engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	assert.Nil(t, decisions, "Evaluate must short-circuit to nil once disabled")

	engine.SetEnabled(true)
	assert.True(t, engine.IsEnabled())

	decisions, err = engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	require.Len(t, decisions, 1)
}

// TestLoadPolicies_RulesDirIsNotADirectory covers the loadPolicies error path
// that is distinct from os.IsNotExist(err): the configured RulesDir exists
// but is a regular file, so os.ReadDir fails with ENOTDIR.
func TestLoadPolicies_RulesDirIsNotADirectory(t *testing.T) {
	tmpDir := t.TempDir()
	notADir := filepath.Join(tmpDir, "not-a-dir")
	require.NoError(t, os.WriteFile(notADir, []byte("hello"), 0644))

	_, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: notADir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load policies")
}

// TestLoadPolicies_SkipsSubdirsAndNonRegoAndTestFiles covers the loadPolicies
// branches for directory entries, non-.rego files, and _test.rego files,
// none of which should be loaded as policies.
func TestLoadPolicies_SkipsSubdirsAndNonRegoAndTestFiles(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "subdir", "nested.rego"), []byte("package x"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("not rego"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "policy_test.rego"), []byte("package x_test"), 0644))

	policy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "r1", "severity": "warning", "message": "m", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "real.rego"), []byte(policy), 0644))

	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.NoError(t, err)

	stats := engine.GetStats()
	assert.Equal(t, 1, stats.PolicyCount, "only real.rego should be loaded")
}

// TestNewRegoEngine_CompileError covers the compile() error path: a
// syntactically invalid .rego file must fail PrepareForEval and NewRegoEngine
// must surface that as a wrapped "compile policies" error.
func TestNewRegoEngine_CompileError(t *testing.T) {
	tmpDir := t.TempDir()
	invalid := `this is not valid rego syntax {{{`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "bad.rego"), []byte(invalid), 0644))

	_, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compile policies")
}

// TestReloadWithContext_LoadPoliciesError drives the loadPolicies error
// branch of ReloadWithContext by mutating the engine's rulesDir (white-box,
// same-package field access) to a non-directory path after successful
// construction.
func TestReloadWithContext_LoadPoliciesError(t *testing.T) {
	tmpDir := t.TempDir()
	policy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "r1", "severity": "warning", "message": "m", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(policy), 0644))

	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.NoError(t, err)

	notADir := filepath.Join(tmpDir, "test.rego") // a regular file, not a dir
	engine.rulesDir = notADir

	err = engine.ReloadWithContext(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reload policies")
}

// TestReloadWithContext_CompileError drives the compile() error branch of
// ReloadWithContext: after a successful initial load, the on-disk policy is
// replaced with invalid Rego syntax before reloading.
func TestReloadWithContext_CompileError(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test.rego")
	validPolicy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "r1", "severity": "warning", "message": "m", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	require.NoError(t, os.WriteFile(policyPath, []byte(validPolicy), 0644))

	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.NoError(t, err)

	invalidPolicy := `this is not valid rego syntax {{{`
	require.NoError(t, os.WriteFile(policyPath, []byte(invalidPolicy), 0644))

	err = engine.ReloadWithContext(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recompile policies")

	// The reload counter must not have been incremented on a failed reload.
	stats := engine.GetStats()
	assert.Equal(t, uint64(0), stats.ReloadCounter)
}

// TestReloadWithContext_EmptyPoliciesClearsCompiledQueries covers the
// compile() early-return branch (len(re.policies) == 0) reached via a
// successful reload after all policy files have been removed.
func TestReloadWithContext_EmptyPoliciesClearsCompiledQueries(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test.rego")
	validPolicy := `
package ebpf_guard
default allow := true
decisions[{"rule_id": "r1", "severity": "warning", "message": "m", "action": "alert", "matched": true}] {
	input.comm == "test"
}
`
	require.NoError(t, os.WriteFile(policyPath, []byte(validPolicy), 0644))

	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.NoError(t, err)

	require.NoError(t, os.Remove(policyPath))
	require.NoError(t, engine.ReloadWithContext(context.Background()))

	alert := types.Alert{
		Comm: "test",
		Event: types.Event{
			Comm: [16]byte{'t', 'e', 's', 't'},
		},
	}
	decisions, err := engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	assert.Nil(t, decisions)

	stats := engine.GetStats()
	assert.Equal(t, uint64(1), stats.ReloadCounter)
	assert.Equal(t, 0, stats.PolicyCount)
}
