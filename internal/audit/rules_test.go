package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRulesLogger(t *testing.T, diffs bool) (*RulesLogger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules-audit.jsonl")
	rl, err := NewRulesLogger(path, 100, diffs)
	require.NoError(t, err)
	return rl, path
}

func readRulesEntries(t *testing.T, path string) []RulesEntry {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	var entries []RulesEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e RulesEntry
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &e))
		entries = append(entries, e)
	}
	require.NoError(t, scanner.Err())
	return entries
}

func TestRulesLogger_LoadedEvent(t *testing.T) {
	rl, path := newTestRulesLogger(t, true)
	defer rl.Close()

	ids := []string{"rule_001", "rule_002", "rule_003"}
	require.NoError(t, rl.LogRulesLoaded("/etc/ebpf-guard/rules.yaml", ids))
	require.NoError(t, rl.Close())

	entries := readRulesEntries(t, path)
	require.Len(t, entries, 1)
	e := entries[0]

	assert.Equal(t, EventRulesLoaded, e.Event)
	assert.Equal(t, "startup", e.Source)
	assert.Equal(t, "/etc/ebpf-guard/rules.yaml", e.RulesFile)
	assert.Equal(t, 3, e.RulesAdded)
	assert.Equal(t, 0, e.RulesRemoved)
	assert.Equal(t, 0, e.RulesModified)
	assert.Empty(t, e.ChecksumBefore)
	assert.NotEmpty(t, e.ChecksumAfter)
	assert.Contains(t, e.ChecksumAfter, "sha256:")
	assert.Equal(t, []string{"rule_001", "rule_002", "rule_003"}, e.NewRuleIDs)
	assert.False(t, e.Timestamp.IsZero())
}

func TestRulesLogger_ReloadedEvent(t *testing.T) {
	rl, path := newTestRulesLogger(t, true)
	defer rl.Close()

	oldIDs := []string{"rule_001", "rule_002", "rule_003"}
	newIDs := []string{"rule_001", "rule_002", "rule_004", "rule_005"}
	require.NoError(t, rl.LogRulesReloaded("fsnotify", "/etc/ebpf-guard/rules.yaml", oldIDs, newIDs))
	require.NoError(t, rl.Close())

	entries := readRulesEntries(t, path)
	require.Len(t, entries, 1)
	e := entries[0]

	assert.Equal(t, EventRulesReloaded, e.Event)
	assert.Equal(t, "fsnotify", e.Source)
	assert.Equal(t, "/etc/ebpf-guard/rules.yaml", e.RulesFile)
	// rule_004 and rule_005 added; rule_003 removed; rule_001 and rule_002 modified
	assert.Equal(t, 2, e.RulesAdded)
	assert.Equal(t, 1, e.RulesRemoved)
	assert.Equal(t, 2, e.RulesModified)
	assert.NotEmpty(t, e.ChecksumBefore)
	assert.NotEmpty(t, e.ChecksumAfter)
	assert.NotEqual(t, e.ChecksumBefore, e.ChecksumAfter)
	assert.Equal(t, []string{"rule_001", "rule_002", "rule_003"}, e.OldRuleIDs)
	assert.Equal(t, []string{"rule_001", "rule_002", "rule_004", "rule_005"}, e.NewRuleIDs)
}

func TestRulesLogger_NoDiffsMode(t *testing.T) {
	rl, path := newTestRulesLogger(t, false)
	defer rl.Close()

	ids := []string{"rule_001", "rule_002"}
	require.NoError(t, rl.LogRulesLoaded("/etc/rules.yaml", ids))
	require.NoError(t, rl.Close())

	entries := readRulesEntries(t, path)
	require.Len(t, entries, 1)
	assert.Nil(t, entries[0].OldRuleIDs)
	assert.Nil(t, entries[0].NewRuleIDs)
	assert.Equal(t, 2, entries[0].RulesAdded)
}

func TestRulesLogger_ConfigReloadedEvent(t *testing.T) {
	rl, path := newTestRulesLogger(t, false)
	defer rl.Close()

	require.NoError(t, rl.LogConfigReloaded("/etc/ebpf-guard/config.yaml"))
	require.NoError(t, rl.Close())

	entries := readRulesEntries(t, path)
	require.Len(t, entries, 1)
	e := entries[0]

	assert.Equal(t, EventConfigReloaded, e.Event)
	assert.Equal(t, "fsnotify", e.Source)
	assert.Equal(t, "/etc/ebpf-guard/config.yaml", e.ConfigFile)
	assert.False(t, e.Timestamp.IsZero())
}

func TestRulesLogger_JSONFieldNames(t *testing.T) {
	rl, path := newTestRulesLogger(t, true)
	defer rl.Close()

	require.NoError(t, rl.LogRulesLoaded("/etc/rules.yaml", []string{"rule_001"}))
	require.NoError(t, rl.Close())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &m))

	assert.Contains(t, m, "timestamp")
	assert.Contains(t, m, "event")
	assert.Contains(t, m, "source")
	assert.Contains(t, m, "rules_file")
	assert.Contains(t, m, "rules_added")
	assert.Contains(t, m, "checksum_after")
}

func TestRulesLogger_ChecksumStability(t *testing.T) {
	ids := []string{"rule_003", "rule_001", "rule_002"}
	cs1 := checksumIDs(ids)
	cs2 := checksumIDs([]string{"rule_001", "rule_002", "rule_003"})
	assert.Equal(t, cs1, cs2, "checksum must be order-independent")
}

func TestRulesLogger_Rotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules-audit.jsonl")
	// 512-byte threshold so rotation can be triggered without large data.
	l, err := newLogger(path, 512)
	require.NoError(t, err)
	rl := &RulesLogger{l: l, includeRuleDiffs: false}
	defer rl.Close()

	ids := []string{"rule_001", "rule_002", "rule_003"}
	for {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		if info.Size() >= 512 {
			break
		}
		require.NoError(t, rl.LogRulesLoaded("/etc/rules.yaml", ids))
	}
	require.NoError(t, rl.LogRulesLoaded("/etc/rules.yaml", ids))
	require.NoError(t, rl.Close())

	_, err = os.Stat(path + ".1")
	require.NoError(t, err, "rotated file must exist at %s.1", path)
}
