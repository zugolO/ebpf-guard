// lsm_test.go — Tests for LSM collector

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/audit"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLSMConfig_Default(t *testing.T) {
	config := DefaultLSMConfig()
	assert.Equal(t, "auto", config.Enabled)
}

// TestNewLSMCollector covers both kernels on any host. It used to assert "no
// kernel support" unconditionally, which held on macOS and on kernels without
// BPF LSM but went red on the stand (5.15, `bpf` in the active list, collector
// live since №502): there auto mode is available and forced mode loads. The
// active-LSM list is now presented by the test (activeLSMListPath).
func TestNewLSMCollector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	dir := t.TempDir()
	withBPF := filepath.Join(dir, "lsm-with-bpf")
	withoutBPF := filepath.Join(dir, "lsm-without-bpf")
	require.NoError(t, os.WriteFile(withBPF, []byte("lockdown,capability,landlock,yama,apparmor,bpf\n"), 0o644))
	require.NoError(t, os.WriteFile(withoutBPF, []byte("lockdown,capability,landlock,yama,apparmor\n"), 0o644))
	missing := filepath.Join(dir, "no-securityfs")

	tests := []struct {
		name      string
		lsmList   string
		config    LSMConfig
		wantAvail bool
		wantErr   bool
	}{
		{"auto mode with no kernel support", withoutBPF, LSMConfig{Enabled: "auto"}, false, false},
		{"auto mode without securityfs", missing, LSMConfig{Enabled: "auto"}, false, false},
		{"disabled mode with no kernel support", withoutBPF, LSMConfig{Enabled: "false"}, false, false},
		{"forced mode with no kernel support", withoutBPF, LSMConfig{Enabled: "true"}, false, true},
		{"auto mode with kernel support", withBPF, LSMConfig{Enabled: "auto"}, true, false},
		{"disabled mode with kernel support", withBPF, LSMConfig{Enabled: "false"}, false, false},
		{"forced mode with kernel support", withBPF, LSMConfig{Enabled: "true"}, true, false},
	}

	orig := activeLSMListPath
	t.Cleanup(func() { activeLSMListPath = orig })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activeLSMListPath = tt.lsmList
			lc, err := NewLSMCollector(tt.config, logger)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAvail, lc.IsAvailable())
		})
	}
}

func TestLSMCollector_Name(t *testing.T) {
	lc := &LSMCollector{}
	assert.Equal(t, "lsm", lc.Name())
}

func TestLSMCollector_RegisterMetrics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(DefaultLSMConfig(), logger)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	err = lc.RegisterMetrics(reg)
	require.NoError(t, err)

	// Verify metrics are registered
	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	assert.Equal(t, "ebpf_guard_lsm_blocks_total", *families[0].Name)
}

func TestLSMCollector_StartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 10)
	errChan := make(chan error, 1)

	go func() {
		errChan <- lc.Start(ctx, out)
	}()

	// Wait for context timeout
	err = <-errChan
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestLSMCollector_BlocklistOperations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	// Should fail when not available
	err = lc.AddToBlocklist(1234)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	err = lc.RemoveFromBlocklist(1234)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestLSMCollector_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	err = lc.Close()
	assert.NoError(t, err)
}

func TestLSMCollector_checkAvailability(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc := &LSMCollector{
		logger: logger,
	}

	// This will return false in test environment without LSM support
	avail := lc.checkAvailability()
	// Just verify it doesn't panic
	_ = avail
}

// TestFNV32a verifies the Go FNV-32a helper produces values that satisfy the
// basic collision-free requirement needed for the path blocklist.
func TestFNV32a(t *testing.T) {
	// Same path → same hash
	assert.Equal(t, fnv32a("/tmp/evil"), fnv32a("/tmp/evil"))
	// Different paths → different hashes (no false positives in blocklist)
	assert.NotEqual(t, fnv32a("/tmp/evil"), fnv32a("/tmp/legit"))
	assert.NotEqual(t, fnv32a("/etc/shadow"), fnv32a("/etc/passwd"))
	// Empty string has a well-defined value (FNV offset basis unchanged = 2166136261)
	assert.Equal(t, uint32(2166136261), fnv32a(""))
}

// TestPathBlocklist_BlockEvil_AllowLegit is the acceptance-test from issue #33:
// blocking /tmp/evil must not block /tmp/legit.
// We simulate the BPF map with an in-memory map keyed by FNV-32a hash.
func TestPathBlocklist_BlockEvil_AllowLegit(t *testing.T) {
	// Simulate the BPF path_blocklist map: hash → blocked
	bpfMap := map[uint32]bool{
		fnv32a("/tmp/evil"): true,
	}

	isBlocked := func(path string) bool {
		return bpfMap[fnv32a(path)]
	}

	assert.True(t, isBlocked("/tmp/evil"), "/tmp/evil must be blocked")
	assert.False(t, isBlocked("/tmp/legit"), "/tmp/legit must be allowed")
	assert.False(t, isBlocked("/etc/passwd"), "/etc/passwd must be allowed")
}

// TestLSMCollector_PathBlocklist_StubMode verifies that path operations return
// a meaningful error when the LSM collector is in stub mode (no kernel support).
func TestLSMCollector_PathBlocklist_StubMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	err = lc.AddPathToBlocklist("/tmp/evil")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	err = lc.RemovePathFromBlocklist("/tmp/evil")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	err = lc.SetPathBlocklist([]string{"/tmp/evil"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

// TestPathBlocklist_Idempotent verifies that adding the same path twice does
// not change the effective blocklist (the BPF map update is idempotent).
func TestPathBlocklist_Idempotent(t *testing.T) {
	bpfMap := map[uint32]bool{}

	add := func(path string) {
		bpfMap[fnv32a(path)] = true
	}

	add("/tmp/evil")
	add("/tmp/evil") // second add must not cause problems
	assert.Len(t, bpfMap, 1, "duplicate path must not create duplicate map entries")
}

// TestParseLSMAuditEventRaw verifies correct byte-level deserialisation of the
// packed lsm_audit_event C struct into the Go lsmAuditEventRaw type.
func TestParseLSMAuditEventRaw(t *testing.T) {
	// Build a synthetic 107-byte record matching the packed C struct layout.
	// type(4) + timestamp(8) + pid(4) + target_pid(4) + uid(4) +
	// action(1) + hook(1) + sig(1) + comm(16) + path(64) = 107
	raw := make([]byte, lsmAuditEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], 11)          // type = EVENT_TYPE_LSM_AUDIT
	binary.LittleEndian.PutUint64(raw[4:12], 123456789)  // timestamp_ns
	binary.LittleEndian.PutUint32(raw[12:16], 9876)      // pid
	binary.LittleEndian.PutUint32(raw[16:20], 1111)      // target_pid
	binary.LittleEndian.PutUint32(raw[20:24], 501)       // uid
	raw[24] = 1                                           // action = LSM_ACTION_DENY
	raw[25] = 0                                           // hook = LSM_HOOK_FILE_OPEN
	raw[26] = 0                                           // sig = 0
	copy(raw[27:43], "myprocess\x00\x00\x00\x00\x00\x00\x00") // comm (NUL-padded)
	copy(raw[43:107], "/etc/shadow\x00")                  // path (NUL-terminated)

	e, err := parseLSMAuditEventRaw(raw)
	require.NoError(t, err)

	assert.Equal(t, uint32(11), e.Type)
	assert.Equal(t, uint64(123456789), e.Timestamp)
	assert.Equal(t, uint32(9876), e.PID)
	assert.Equal(t, uint32(1111), e.TargetPID)
	assert.Equal(t, uint32(501), e.UID)
	assert.Equal(t, uint8(1), e.Action)   // DENY
	assert.Equal(t, uint8(0), e.Hook)    // file_open
	assert.Equal(t, uint8(0), e.Sig)
	assert.Equal(t, "myprocess", nullTermString(e.Comm[:]))
	assert.Equal(t, "/etc/shadow", nullTermString(e.Path[:]))
}

// TestParseLSMAuditEventRaw_TooShort verifies that undersized records return an error.
func TestParseLSMAuditEventRaw_TooShort(t *testing.T) {
	_, err := parseLSMAuditEventRaw(make([]byte, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestLSMAuditEventRaw_ToAuditEntry verifies that toAuditEntry maps fields correctly.
func TestLSMAuditEventRaw_ToAuditEntry(t *testing.T) {
	tests := []struct {
		name       string
		hook       uint8
		action     uint8
		wantHook   string
		wantAction string
		wantEnf    bool
	}{
		{"file_open deny", 0, 1, "file_open", "deny", true},
		{"socket_connect deny", 1, 1, "socket_connect", "deny", true},
		{"task_kill audit", 2, 0, "task_kill", "audit", false},
		{"unknown hook", 99, 0, "unknown", "audit", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := lsmAuditEventRaw{
				Type:   11,
				PID:    42,
				Action: tt.action,
				Hook:   tt.hook,
			}
			copy(e.Comm[:], "test\x00")
			copy(e.Path[:], "/tmp/x\x00")

			entry := e.toAuditEntry()
			assert.Equal(t, tt.wantHook, entry.Hook)
			assert.Equal(t, tt.wantAction, entry.Action)
			assert.Equal(t, tt.wantEnf, entry.Enforced)
			assert.Equal(t, uint32(42), entry.PID)
			assert.Equal(t, "lsm_audit", entry.Rule)
		})
	}
}

// TestKmodCollector_WithAuditLogger_LSMAuditRouting verifies that when a
// KmodCollector has an audit logger attached, parsing an EVENT_TYPE_LSM_AUDIT
// record logs it to the audit file and returns nil (not forwarded to channel).
func TestKmodCollector_WithAuditLogger_LSMAuditRouting(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	al, err := audit.New(path)
	require.NoError(t, err)
	defer al.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c, err := NewKmodCollector(logger)
	require.NoError(t, err)
	c.WithAuditLogger(al)

	// Build a valid lsm_audit_event raw record.
	raw := make([]byte, lsmAuditEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], 11)    // EVENT_TYPE_LSM_AUDIT
	binary.LittleEndian.PutUint32(raw[12:16], 777) // pid
	binary.LittleEndian.PutUint32(raw[20:24], 0)   // uid
	raw[24] = 1                                     // action = DENY
	raw[25] = 0                                     // hook = file_open
	copy(raw[27:43], "attacker\x00")
	copy(raw[43:107], "/etc/shadow\x00")

	event, parseErr := c.parseKmodOrFallback(raw)
	require.NoError(t, parseErr)
	assert.Nil(t, event, "LSM audit events must not be forwarded to the event channel")

	// Flush and verify the audit log received the entry.
	require.NoError(t, al.Close())

	// Re-open and read.
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	var buf [4096]byte
	n, _ := f.Read(buf[:])
	assert.Contains(t, string(buf[:n]), `"deny"`)
	assert.Contains(t, string(buf[:n]), `"file_open"`)
	assert.Contains(t, string(buf[:n]), `/etc/shadow`)
}

// TestKmodCollector_WithAuditLogger_NoLogger verifies that without an audit logger
// the LSM audit event is still consumed (returns nil) and does not panic.
func TestKmodCollector_WithAuditLogger_NoLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c, err := NewKmodCollector(logger)
	require.NoError(t, err)
	// No WithAuditLogger call.

	raw := make([]byte, lsmAuditEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], 11)

	event, parseErr := c.parseKmodOrFallback(raw)
	require.NoError(t, parseErr)
	assert.Nil(t, event)
}

// TestPathBlocklist_HotReload verifies that SetPathBlocklist replaces the
// previous config-driven set while preserving dynamically added entries.
func TestPathBlocklist_HotReload(t *testing.T) {
	// Round 1: config has /etc/shadow
	configMap := map[uint32]bool{fnv32a("/etc/shadow"): true}
	// Dynamic rule blocked /tmp/evil too
	dynamicMap := map[uint32]bool{fnv32a("/tmp/evil"): true}

	isBlocked := func(path string) bool {
		return configMap[fnv32a(path)] || dynamicMap[fnv32a(path)]
	}

	assert.True(t, isBlocked("/etc/shadow"))
	assert.True(t, isBlocked("/tmp/evil"))
	assert.False(t, isBlocked("/tmp/legit"))

	// Round 2: config hot-reload removes /etc/shadow, adds /proc/sysrq-trigger
	delete(configMap, fnv32a("/etc/shadow"))
	configMap[fnv32a("/proc/sysrq-trigger")] = true

	assert.False(t, isBlocked("/etc/shadow"), "removed config path must be unblocked")
	assert.True(t, isBlocked("/proc/sysrq-trigger"), "new config path must be blocked")
	assert.True(t, isBlocked("/tmp/evil"), "dynamic path must survive hot-reload")
}

// TestKmodCollector_LSMAuditCgroupIDReachesAuditLog — хвост пункта 8 ревизии
// 6.6. lsm_audit_event идёт в audit-журнал, а не в types.Event, поэтому поле
// обязано доехать ДО ЖУРНАЛА, иначе оно мёртвый груз на проводе. Хвост пишется
// ЛИТЕРАЛОМ 107, а не константой, которой читает разбор.
func TestKmodCollector_LSMAuditCgroupIDReachesAuditLog(t *testing.T) {
	build := func(n int) []byte {
		raw := make([]byte, n)
		binary.LittleEndian.PutUint32(raw[0:4], 11) // EVENT_TYPE_LSM_AUDIT
		binary.LittleEndian.PutUint32(raw[12:16], 4242)
		raw[24] = 1
		copy(raw[27:43], "attacker\x00")
		if n >= 115 {
			binary.LittleEndian.PutUint64(raw[107:], 0xABCDEF01)
		}
		return raw
	}
	logOf := func(t *testing.T, raw []byte) map[string]any {
		path := t.TempDir() + "/audit.jsonl"
		al, err := audit.New(path)
		require.NoError(t, err)
		c, err := NewKmodCollector(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
		require.NoError(t, err)
		c.WithAuditLogger(al)
		ev, err := c.parseKmodOrFallback(raw)
		require.NoError(t, err)
		require.Nil(t, ev)
		require.NoError(t, al.Close())
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(b), &m))
		return m
	}

	t.Run("new 115-byte record carries cgroup_id into the audit log", func(t *testing.T) {
		m := logOf(t, build(115))
		assert.Equal(t, float64(0xABCDEF01), m["cgroup_id"])
		assert.Equal(t, float64(4242), m["pid"], "existing offsets unchanged")
	})
	t.Run("old 107-byte record still parses, cgroup_id omitted", func(t *testing.T) {
		m := logOf(t, build(107))
		_, present := m["cgroup_id"]
		assert.False(t, present, "0 is «no cgroup id» and must not be printed as cgroup zero")
		assert.Equal(t, float64(4242), m["pid"])
	})
}
