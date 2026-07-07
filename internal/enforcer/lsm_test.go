package enforcer

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fakeLSM is a test-local implementation of LSMBlocklistManager. It records
// every call and lets tests inject availability and per-method errors, so
// assertions can verify the real resulting state (which paths/PIDs ended up
// blocked) rather than merely "the mock was called".
type fakeLSM struct {
	mu sync.Mutex

	available bool

	addErr        error // AddToBlocklist
	removeErr     error // RemoveFromBlocklist
	addPathErr    error // AddPathToBlocklist
	removePathErr error // RemovePathFromBlocklist
	setPathErr    error // SetPathBlocklist

	blockedPIDs  map[uint32]struct{}
	blockedPaths map[string]struct{}

	addPIDCalls  []uint32
	addPathCalls []string
	setPathCalls int
	configPaths  []string // last SetPathBlocklist argument (copy)
}

func newFakeLSM(available bool) *fakeLSM {
	return &fakeLSM{
		available:    available,
		blockedPIDs:  make(map[uint32]struct{}),
		blockedPaths: make(map[string]struct{}),
	}
}

func (f *fakeLSM) IsAvailable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available
}

func (f *fakeLSM) AddToBlocklist(pid uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addPIDCalls = append(f.addPIDCalls, pid)
	if f.addErr != nil {
		return f.addErr
	}
	f.blockedPIDs[pid] = struct{}{}
	return nil
}

func (f *fakeLSM) RemoveFromBlocklist(pid uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.blockedPIDs, pid)
	return nil
}

func (f *fakeLSM) AddPathToBlocklist(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addPathCalls = append(f.addPathCalls, path)
	if f.addPathErr != nil {
		return f.addPathErr
	}
	f.blockedPaths[path] = struct{}{}
	return nil
}

func (f *fakeLSM) RemovePathFromBlocklist(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removePathErr != nil {
		return f.removePathErr
	}
	delete(f.blockedPaths, path)
	return nil
}

func (f *fakeLSM) SetPathBlocklist(paths []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setPathCalls++
	f.configPaths = append([]string(nil), paths...)
	if f.setPathErr != nil {
		return f.setPathErr
	}
	for _, p := range paths {
		f.blockedPaths[p] = struct{}{}
	}
	return nil
}

// hasPID reports whether the fake currently has pid in its blocklist state.
func (f *fakeLSM) hasPID(pid uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.blockedPIDs[pid]
	return ok
}

// hasPath reports whether the fake currently has path in its blocklist state.
func (f *fakeLSM) hasPath(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.blockedPaths[path]
	return ok
}

// fileAlert builds a file-access alert whose FileEvent.Filename holds path.
func fileAlert(ruleID, path string, pid, uid uint32) types.Alert {
	var fn [256]byte
	copy(fn[:], path)
	return types.Alert{
		RuleID: ruleID,
		Event: types.Event{
			PID:  pid,
			UID:  uid,
			Type: types.EventFileAccess,
			File: &types.FileEvent{Filename: fn},
		},
	}
}

func TestExtractFilePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		alert types.Alert
		want  string
	}{
		{
			name:  "nil file event",
			alert: types.Alert{Event: types.Event{Type: types.EventFileAccess}},
			want:  "",
		},
		{
			name:  "empty filename",
			alert: fileAlert("r", "", 10, 0),
			want:  "",
		},
		{
			name:  "embedded null truncation",
			alert: fileAlert("r", "/etc/passwd\x00trailing-garbage", 10, 0),
			want:  "/etc/passwd",
		},
		{
			name:  "cleaned path",
			alert: fileAlert("r", "/var/lib/../log/./syslog", 10, 0),
			want:  "/var/log/syslog",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, extractFilePath(tt.alert))
		})
	}
}

func TestApplyLSMConfigPaths(t *testing.T) {
	t.Parallel()

	t.Run("nil manager is no-op", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, ApplyLSMConfigPaths(nil, []string{"/a", "/b"}))
	})

	t.Run("unavailable manager does not set paths", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(false)
		require.NoError(t, ApplyLSMConfigPaths(f, []string{"/a", "/b"}))
		assert.Equal(t, 0, f.setPathCalls, "SetPathBlocklist must not be called when unavailable")
		assert.False(t, f.hasPath("/a"))
	})

	t.Run("available manager sets exact paths", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(true)
		paths := []string{"/usr/bin/nc", "/tmp/evil"}
		require.NoError(t, ApplyLSMConfigPaths(f, paths))
		assert.Equal(t, 1, f.setPathCalls)
		assert.Equal(t, paths, f.configPaths, "SetPathBlocklist got exactly the given paths")
		assert.True(t, f.hasPath("/usr/bin/nc"))
		assert.True(t, f.hasPath("/tmp/evil"))
	})

	t.Run("SetPathBlocklist error is wrapped", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(true)
		f.setPathErr = errors.New("bpf map full")
		err := ApplyLSMConfigPaths(f, []string{"/x"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "apply config path blocklist")
		assert.ErrorContains(t, err, "bpf map full")
	})
}

func TestExecuteLSMBlockFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("dry run logs only, nothing blocked", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(true)
		e, err := NewEnforcer(testLogger(), Config{DryRun: true, LSMManager: f})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close() })

		alert := fileAlert("rule_dry", "/tmp/x", 100, 0)
		require.NoError(t, e.executeLSMBlockFile(ctx, alert))
		assert.False(t, f.hasPath("/tmp/x"), "dry-run must not add path")
		assert.Empty(t, f.addPathCalls)
	})

	t.Run("no path returns error", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(true)
		e, err := NewEnforcer(testLogger(), Config{LSMManager: f})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close() })

		alert := types.Alert{RuleID: "r", Event: types.Event{Type: types.EventFileAccess}} // File nil
		err = e.executeLSMBlockFile(ctx, alert)
		require.Error(t, err)
		assert.ErrorContains(t, err, "no path")
	})

	t.Run("lsm unavailable returns error", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(false)
		e, err := NewEnforcer(testLogger(), Config{LSMManager: f})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close() })

		alert := fileAlert("r", "/tmp/x", 100, 0)
		err = e.executeLSMBlockFile(ctx, alert)
		require.Error(t, err)
		assert.ErrorContains(t, err, "LSM not available")
		assert.Empty(t, f.addPathCalls)
	})

	t.Run("success records exact cleaned path", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(true)
		e, err := NewEnforcer(testLogger(), Config{LSMManager: f})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close() })

		alert := fileAlert("r", "/tmp/../etc/shadow", 100, 0)
		require.NoError(t, e.executeLSMBlockFile(ctx, alert))
		assert.True(t, f.hasPath("/etc/shadow"), "cleaned path must be in blocklist")
		assert.Equal(t, []string{"/etc/shadow"}, f.addPathCalls)
	})

	t.Run("AddPathToBlocklist error is wrapped", func(t *testing.T) {
		t.Parallel()
		f := newFakeLSM(true)
		f.addPathErr = errors.New("map insert failed")
		e, err := NewEnforcer(testLogger(), Config{LSMManager: f})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close() })

		alert := fileAlert("r", "/tmp/x", 100, 0)
		err = e.executeLSMBlockFile(ctx, alert)
		require.Error(t, err)
		assert.ErrorContains(t, err, "add path")
		assert.ErrorContains(t, err, "map insert failed")
	})
}
