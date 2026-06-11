package osint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
)

// newManagerForCache builds a Manager purely for state-persistence testing.
func newManagerForCache(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(config.OSINTConfig{
		Enabled:   true,
		OutputDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// --- State TTL / incremental-sync tests ---

func TestCache_NewStateIsEmpty(t *testing.T) {
	m := newManagerForCache(t)
	state := m.loadState()
	if len(state.LastSync) != 0 {
		t.Errorf("new state should have empty LastSync, got %v", state.LastSync)
	}
	if len(state.RuleFiles) != 0 {
		t.Errorf("new state should have empty RuleFiles, got %v", state.RuleFiles)
	}
}

func TestCache_SaveAndLoad_PreservesTimestamp(t *testing.T) {
	m := newManagerForCache(t)
	ts := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

	state := SyncState{
		LastSync:  map[Source]time.Time{SourceMISP: ts},
		RuleFiles: map[string]string{},
	}
	m.saveState(state)

	loaded := m.loadState()
	got, ok := loaded.LastSync[SourceMISP]
	if !ok {
		t.Fatal("SourceMISP not found after save/load")
	}
	if !got.Equal(ts) {
		t.Errorf("timestamp mismatch: want %v got %v", ts, got)
	}
}

func TestCache_SaveAndLoad_MultipleSourceTimestamps(t *testing.T) {
	m := newManagerForCache(t)

	timestamps := map[Source]time.Time{
		SourceMISP:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SourceOpenCTI:    time.Date(2026, 2, 1, 6, 30, 0, 0, time.UTC),
		SourceVirusTotal: time.Date(2026, 3, 1, 23, 59, 59, 0, time.UTC),
	}
	m.saveState(SyncState{LastSync: timestamps, RuleFiles: map[string]string{}})

	loaded := m.loadState()
	for src, want := range timestamps {
		got, ok := loaded.LastSync[src]
		if !ok {
			t.Errorf("source %s not found after save/load", src)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("source %s: want %v, got %v", src, want, got)
		}
	}
}

func TestCache_Overwrite_UpdatesTimestamp(t *testing.T) {
	m := newManagerForCache(t)

	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	second := first.Add(24 * time.Hour)

	m.saveState(SyncState{
		LastSync:  map[Source]time.Time{SourceMISP: first},
		RuleFiles: map[string]string{},
	})
	m.saveState(SyncState{
		LastSync:  map[Source]time.Time{SourceMISP: second},
		RuleFiles: map[string]string{},
	})

	loaded := m.loadState()
	if !loaded.LastSync[SourceMISP].Equal(second) {
		t.Errorf("expected updated timestamp %v, got %v", second, loaded.LastSync[SourceMISP])
	}
}

func TestCache_EvictSource_RemovedFromState(t *testing.T) {
	m := newManagerForCache(t)

	ts := time.Now().UTC()
	initial := SyncState{
		LastSync: map[Source]time.Time{
			SourceMISP:    ts,
			SourceOpenCTI: ts,
		},
		RuleFiles: map[string]string{},
	}
	m.saveState(initial)

	// Evict MISP by writing a state without it.
	evicted := m.loadState()
	delete(evicted.LastSync, SourceMISP)
	m.saveState(evicted)

	reloaded := m.loadState()
	if _, ok := reloaded.LastSync[SourceMISP]; ok {
		t.Error("expected SourceMISP to be evicted from state")
	}
	if _, ok := reloaded.LastSync[SourceOpenCTI]; !ok {
		t.Error("expected SourceOpenCTI to remain in state")
	}
}

func TestCache_RuleFileHashes_Persisted(t *testing.T) {
	m := newManagerForCache(t)

	hashes := map[string]string{
		"osint_misp_ip_001.yaml":     "aabbcc",
		"osint_opencti_domain_001.yaml": "ddeeff",
	}
	m.saveState(SyncState{
		LastSync:  map[Source]time.Time{},
		RuleFiles: hashes,
	})

	loaded := m.loadState()
	for name, want := range hashes {
		got, ok := loaded.RuleFiles[name]
		if !ok {
			t.Errorf("rule file %q not found after save/load", name)
			continue
		}
		if got != want {
			t.Errorf("rule file %q: want hash %q, got %q", name, want, got)
		}
	}
}

func TestCache_CorruptFile_ReturnsCleanState(t *testing.T) {
	m := newManagerForCache(t)

	if err := os.WriteFile(m.statePath, []byte("{{invalid json{{"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}

	state := m.loadState()
	if state.LastSync == nil {
		t.Error("LastSync should be non-nil after corrupt state recovery")
	}
	if state.RuleFiles == nil {
		t.Error("RuleFiles should be non-nil after corrupt state recovery")
	}
	if len(state.LastSync) != 0 {
		t.Error("LastSync should be empty after corrupt state recovery")
	}
}

func TestCache_PartiallyCorruptJSON_ReturnsCleanState(t *testing.T) {
	m := newManagerForCache(t)

	// Write JSON that is syntactically valid but missing required map fields.
	partial := `{"last_sync": null, "rule_files": null}`
	if err := os.WriteFile(m.statePath, []byte(partial), 0o600); err != nil {
		t.Fatalf("write partial state: %v", err)
	}

	state := m.loadState()
	if state.LastSync == nil {
		t.Error("LastSync must be initialised even when JSON value is null")
	}
	if state.RuleFiles == nil {
		t.Error("RuleFiles must be initialised even when JSON value is null")
	}
}

func TestCache_MissingFile_ReturnsCleanState(t *testing.T) {
	m := newManagerForCache(t)
	// Ensure the file does not exist.
	_ = os.Remove(m.statePath)

	state := m.loadState()
	if state.LastSync == nil || state.RuleFiles == nil {
		t.Error("state should never be nil even when file is absent")
	}
}

func TestCache_FilePermissions_RestrictedToOwner(t *testing.T) {
	m := newManagerForCache(t)

	m.saveState(SyncState{
		LastSync:  map[Source]time.Time{SourceMISP: time.Now()},
		RuleFiles: map[string]string{},
	})

	info, err := os.Stat(m.statePath)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if info.Mode()&0o077 != 0 {
		t.Errorf("state file permissions too permissive: %v", info.Mode())
	}
}

func TestCache_JSONSchema_Matches(t *testing.T) {
	m := newManagerForCache(t)
	ts := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	m.saveState(SyncState{
		LastSync:  map[Source]time.Time{SourceMISP: ts},
		RuleFiles: map[string]string{"foo.yaml": "deadbeef"},
	})

	raw, err := os.ReadFile(m.statePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}

	var generic map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("state file is not valid JSON: %v", err)
	}
	if _, ok := generic["last_sync"]; !ok {
		t.Error("state JSON missing 'last_sync' key")
	}
	if _, ok := generic["rule_files"]; !ok {
		t.Error("state JSON missing 'rule_files' key")
	}
}

// --- Concurrent access tests ---

func TestCache_ConcurrentSaveLoad(t *testing.T) {
	m := newManagerForCache(t)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			src := SourceMISP
			if i%2 == 0 {
				src = SourceOpenCTI
			}
			ts := time.Now().UTC().Add(time.Duration(i) * time.Second)
			m.saveState(SyncState{
				LastSync:  map[Source]time.Time{src: ts},
				RuleFiles: map[string]string{},
			})
			m.loadState()
		}(i)
	}
	wg.Wait()
}

func TestCache_ConcurrentSaveLoad_NoDataRace(t *testing.T) {
	// This test is designed to surface data races when run with -race.
	m := newManagerForCache(t)

	ts := time.Now().UTC()
	state := SyncState{
		LastSync:  map[Source]time.Time{SourceMISP: ts},
		RuleFiles: map[string]string{"a.yaml": "hash"},
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			m.saveState(state)
		}()
		go func() {
			defer wg.Done()
			m.loadState()
		}()
	}
	wg.Wait()
}

func TestCache_StateFilePath_IsInsideOutputDir(t *testing.T) {
	m := newManagerForCache(t)
	if !filepath.IsAbs(m.statePath) {
		t.Errorf("statePath should be absolute: %q", m.statePath)
	}
	rel, err := filepath.Rel(m.cfg.OutputDir, m.statePath)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	if rel == ".." || filepath.IsAbs(rel) {
		t.Errorf("statePath %q should be inside OutputDir %q", m.statePath, m.cfg.OutputDir)
	}
}
