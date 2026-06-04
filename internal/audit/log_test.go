package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path)
	require.NoError(t, err)
	return l, path
}

func readEntries(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &e))
		entries = append(entries, e)
	}
	require.NoError(t, scanner.Err())
	return entries
}

func TestLogger_AppendJSONL(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	entries := []Entry{
		{TS: time.Now(), Action: "kill", PID: 1234, Rule: "rule_001", Comm: "bash", Enforced: true},
		{TS: time.Now(), Action: "block", PID: 5678, Rule: "rule_002", Comm: "curl", Enforced: false},
		{TS: time.Now(), Action: "throttle", PID: 9, Rule: "rule_003", Comm: "nc", Enforced: true},
	}
	for _, e := range entries {
		require.NoError(t, l.Log(e))
	}
	require.NoError(t, l.Close())

	got := readEntries(t, path)
	require.Len(t, got, 3)
	assert.Equal(t, "kill", got[0].Action)
	assert.Equal(t, uint32(1234), got[0].PID)
	assert.Equal(t, "rule_001", got[0].Rule)
	assert.Equal(t, "bash", got[0].Comm)
	assert.True(t, got[0].Enforced)
	assert.Equal(t, "block", got[1].Action)
	assert.False(t, got[1].Enforced)
}

func TestLogger_JSONFieldNames(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	ts := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	require.NoError(t, l.Log(Entry{TS: ts, Action: "kill", PID: 42, Rule: "r1", Comm: "sh", Enforced: true}))
	require.NoError(t, l.Close())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &m))

	assert.Contains(t, m, "ts")
	assert.Contains(t, m, "action")
	assert.Contains(t, m, "pid")
	assert.Contains(t, m, "rule")
	assert.Contains(t, m, "comm")
	assert.Contains(t, m, "enforced")
	// Verify no unexpected snake_case aliases
	assert.NotContains(t, m, "timestamp")
	assert.NotContains(t, m, "rule_id")
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	const writers = 8
	const perWriter = 50

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				_ = l.Log(Entry{
					TS:       time.Now(),
					Action:   "kill",
					PID:      uint32(id*100 + j),
					Rule:     "rule_concurrent",
					Comm:     "test",
					Enforced: true,
				})
			}
		}(i)
	}
	wg.Wait()
	require.NoError(t, l.Close())

	got := readEntries(t, path)
	assert.Len(t, got, writers*perWriter)
}

func TestLogger_Rotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Use a 500-byte threshold so we can trigger rotation without writing 100 MB.
	l, err := newLogger(path, 500)
	require.NoError(t, err)
	defer l.Close()

	// Write entries until the file exceeds 500 bytes.
	e := Entry{TS: time.Now(), Action: "kill", PID: 1, Rule: "rule_001", Comm: "bash", Enforced: true}
	for {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		if info.Size() >= 500 {
			break
		}
		require.NoError(t, l.Log(e))
	}

	// This write crosses the threshold and must trigger rotation.
	require.NoError(t, l.Log(Entry{Action: "block", PID: 2, Rule: "rule_002", Comm: "nc", Enforced: false}))
	require.NoError(t, l.Close())

	// Old data must have been moved to .1
	_, err = os.Stat(path + ".1")
	require.NoError(t, err, "rotated file must exist at %s.1", path)

	// The new active file contains only the entry written after rotation.
	entries := readEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, "block", entries[0].Action)
}

func TestLogger_DirectoryCreation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	path := filepath.Join(dir, "audit.jsonl")

	l, err := New(path)
	require.NoError(t, err)
	defer l.Close()

	require.NoError(t, l.Log(Entry{Action: "block", PID: 99, Rule: "r", Comm: "x", Enforced: false}))
	require.NoError(t, l.Close())

	got := readEntries(t, path)
	require.Len(t, got, 1)
}

func TestLogger_AppendToExisting(t *testing.T) {
	l, path := newTestLogger(t)
	require.NoError(t, l.Log(Entry{Action: "kill", PID: 1, Rule: "r1", Comm: "a", Enforced: true}))
	require.NoError(t, l.Close())

	// Re-open and append
	l2, err := New(path)
	require.NoError(t, err)
	require.NoError(t, l2.Log(Entry{Action: "block", PID: 2, Rule: "r2", Comm: "b", Enforced: false}))
	require.NoError(t, l2.Close())

	got := readEntries(t, path)
	require.Len(t, got, 2)
	assert.Equal(t, "kill", got[0].Action)
	assert.Equal(t, "block", got[1].Action)
}
