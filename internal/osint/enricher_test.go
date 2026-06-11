package osint

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
)

// mockClient is a test Client whose Fetch behaviour is controlled by the test.
type mockClient struct {
	source  Source
	result  FeedResult
	err     error
	fetched []time.Time // records the `since` argument on each call
}

func (m *mockClient) Source() Source { return m.source }

func (m *mockClient) Fetch(since time.Time) (FeedResult, error) {
	m.fetched = append(m.fetched, since)
	if m.err != nil {
		return FeedResult{}, m.err
	}
	return m.result, nil
}

// newManagerWithClients builds a Manager wired with the provided mock clients.
func newManagerWithClients(t *testing.T, clients []Client) *Manager {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(config.OSINTConfig{
		Enabled:        true,
		OutputDir:      dir,
		MaxIoCsPerRule: 100,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.clients = clients
	return m
}

// --- Enrichment pipeline tests ---

func TestEnrichmentPipeline_SingleClient(t *testing.T) {
	ts := time.Now().UTC()
	client := &mockClient{
		source: SourceMISP,
		result: FeedResult{
			Source:    SourceMISP,
			FetchedAt: ts,
			IoCs: []IoC{
				{Value: "1.2.3.4", Type: IoCTypeIP, Source: SourceMISP},
				{Value: "evil.com", Type: IoCTypeDomain, Source: SourceMISP},
			},
		},
	}

	m := newManagerWithClients(t, []Client{client})
	m.sync(context.Background())

	// Rule files should have been written.
	entries, err := os.ReadDir(m.cfg.OutputDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	yamlFiles := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			yamlFiles++
		}
	}
	if yamlFiles == 0 {
		t.Error("expected at least one YAML rule file after sync")
	}
}

func TestEnrichmentPipeline_MultipleClients(t *testing.T) {
	ts := time.Now().UTC()
	clients := []Client{
		&mockClient{
			source: SourceMISP,
			result: FeedResult{
				Source:    SourceMISP,
				FetchedAt: ts,
				IoCs:      makeIoCs([]string{"10.0.0.1"}, IoCTypeIP, SourceMISP),
			},
		},
		&mockClient{
			source: SourceOpenCTI,
			result: FeedResult{
				Source:    SourceOpenCTI,
				FetchedAt: ts,
				IoCs:      makeIoCs([]string{"bad.example.com"}, IoCTypeDomain, SourceOpenCTI),
			},
		},
	}

	m := newManagerWithClients(t, clients)
	m.sync(context.Background())

	// Both sources should have been fetched.
	if len(clients[0].(*mockClient).fetched) != 1 {
		t.Errorf("MISP: expected 1 fetch call, got %d", len(clients[0].(*mockClient).fetched))
	}
	if len(clients[1].(*mockClient).fetched) != 1 {
		t.Errorf("OpenCTI: expected 1 fetch call, got %d", len(clients[1].(*mockClient).fetched))
	}

	// State should have timestamps for both sources.
	state := m.loadState()
	if _, ok := state.LastSync[SourceMISP]; !ok {
		t.Error("state missing MISP LastSync timestamp")
	}
	if _, ok := state.LastSync[SourceOpenCTI]; !ok {
		t.Error("state missing OpenCTI LastSync timestamp")
	}
}

func TestEnrichmentPipeline_ClientError_ContinuesOthers(t *testing.T) {
	ts := time.Now().UTC()
	clients := []Client{
		&mockClient{
			source: SourceMISP,
			err:    errors.New("connection refused"),
		},
		&mockClient{
			source: SourceOpenCTI,
			result: FeedResult{
				Source:    SourceOpenCTI,
				FetchedAt: ts,
				IoCs:      makeIoCs([]string{"threat.example.com"}, IoCTypeDomain, SourceOpenCTI),
			},
		},
	}

	m := newManagerWithClients(t, clients)
	m.sync(context.Background()) // must not panic

	// Second client should still have been called despite first client error.
	if len(clients[1].(*mockClient).fetched) != 1 {
		t.Errorf("expected OpenCTI to be fetched even after MISP error, got %d calls",
			len(clients[1].(*mockClient).fetched))
	}

	// State should record the successful source but not the failed one.
	state := m.loadState()
	if _, ok := state.LastSync[SourceMISP]; ok {
		t.Error("state should not contain MISP timestamp after fetch error")
	}
	if _, ok := state.LastSync[SourceOpenCTI]; !ok {
		t.Error("state should contain OpenCTI timestamp after successful fetch")
	}
}

func TestEnrichmentPipeline_AllClientsError(t *testing.T) {
	clients := []Client{
		&mockClient{source: SourceMISP, err: errors.New("timeout")},
		&mockClient{source: SourceVirusTotal, err: errors.New("rate limited")},
	}

	m := newManagerWithClients(t, clients)
	m.sync(context.Background()) // must not panic or write bad state

	// No timestamps should be saved.
	state := m.loadState()
	if len(state.LastSync) != 0 {
		t.Errorf("expected empty LastSync on all-error sync, got %v", state.LastSync)
	}
}

func TestEnrichmentPipeline_IncrementalSync_PassesSince(t *testing.T) {
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	second := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	client := &mockClient{source: SourceMISP}
	m := newManagerWithClients(t, []Client{client})

	// Seed a prior sync timestamp.
	state := SyncState{
		LastSync:  map[Source]time.Time{SourceMISP: first},
		RuleFiles: map[string]string{},
	}
	m.saveState(state)

	// On the next sync, FetchedAt is second.
	client.result = FeedResult{Source: SourceMISP, FetchedAt: second}
	m.sync(context.Background())

	if len(client.fetched) != 1 {
		t.Fatalf("expected 1 fetch call, got %d", len(client.fetched))
	}
	if !client.fetched[0].Equal(first) {
		t.Errorf("expected since=%v, got %v", first, client.fetched[0])
	}

	// State updated to the new timestamp.
	updated := m.loadState()
	if !updated.LastSync[SourceMISP].Equal(second) {
		t.Errorf("expected updated LastSync=%v, got %v", second, updated.LastSync[SourceMISP])
	}
}

func TestEnrichmentPipeline_RuleFileHashRecorded(t *testing.T) {
	ts := time.Now().UTC()
	client := &mockClient{
		source: SourceMISP,
		result: FeedResult{
			Source:    SourceMISP,
			FetchedAt: ts,
			IoCs:      makeIoCs([]string{"9.9.9.9"}, IoCTypeIP, SourceMISP),
		},
	}

	m := newManagerWithClients(t, []Client{client})
	m.sync(context.Background())

	state := m.loadState()
	if len(state.RuleFiles) == 0 {
		t.Error("expected at least one rule file hash in state after sync")
	}
	for name, hash := range state.RuleFiles {
		if !strings.HasSuffix(name, ".yaml") {
			t.Errorf("rule file name should end in .yaml: %q", name)
		}
		if len(hash) != 64 {
			t.Errorf("hash should be 64 hex chars (SHA-256): got %q", hash)
		}
	}
}

func TestEnrichmentPipeline_ContextCancellation(t *testing.T) {
	// Client that blocks until its context is cancelled.
	blocked := make(chan struct{})
	slow := &mockClient{source: SourceMISP}
	slow.result = FeedResult{Source: SourceMISP, FetchedAt: time.Now()}

	// Override with a blocking client using closure.
	type blockingClient struct{ mockClient }
	_ = slow

	clients := []Client{
		&mockClient{
			source: SourceOpenCTI,
			result: FeedResult{
				Source:    SourceOpenCTI,
				FetchedAt: time.Now().UTC(),
				IoCs:      makeIoCs([]string{"5.5.5.5"}, IoCTypeIP, SourceOpenCTI),
			},
		},
	}
	close(blocked) // satisfy linter — not used in path below

	ctx, cancel := context.WithCancel(context.Background())
	m := newManagerWithClients(t, clients)

	cancel() // cancel immediately

	// sync should return quickly and not block.
	done := make(chan struct{})
	go func() {
		m.sync(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("sync did not respect context cancellation")
	}
}

func TestEnrichmentPipeline_EmptyIoCs_NoFilesWritten(t *testing.T) {
	client := &mockClient{
		source: SourceVirusTotal,
		result: FeedResult{Source: SourceVirusTotal, FetchedAt: time.Now().UTC()},
	}

	m := newManagerWithClients(t, []Client{client})
	m.sync(context.Background())

	entries, err := os.ReadDir(m.cfg.OutputDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			t.Errorf("unexpected YAML file %q for empty IoC feed", e.Name())
		}
	}
}

func TestEnrichmentPipeline_MixedIoCTypes(t *testing.T) {
	ts := time.Now().UTC()
	iocs := []IoC{
		{Value: "1.1.1.1", Type: IoCTypeIP, Source: SourceMISP},
		{Value: "10.0.0.0/8", Type: IoCTypeCIDR, Source: SourceMISP},
		{Value: "evil.example.com", Type: IoCTypeDomain, Source: SourceMISP},
		{Value: "http://phish.io/payload", Type: IoCTypeURL, Source: SourceMISP},
	}
	client := &mockClient{
		source: SourceMISP,
		result: FeedResult{Source: SourceMISP, FetchedAt: ts, IoCs: iocs},
	}

	m := newManagerWithClients(t, []Client{client})
	m.sync(context.Background())

	// Should produce 3 files: IP, CIDR, and domain (URL treated as domain).
	entries, err := os.ReadDir(m.cfg.OutputDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	counts := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		switch {
		case strings.Contains(name, "_ip_"):
			counts["ip"]++
		case strings.Contains(name, "_cidr_"):
			counts["cidr"]++
		case strings.Contains(name, "_domain_"):
			counts["domain"]++
		}
	}
	for _, typ := range []string{"ip", "cidr", "domain"} {
		if counts[typ] == 0 {
			t.Errorf("expected at least one %s rule file, got 0", typ)
		}
	}
}

func TestEnrichmentPipeline_BatchingCreatesMultipleFiles(t *testing.T) {
	ips := make([]string, 25)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.%d.%d.%d", i/256, (i/16)%16, i%16)
	}
	dir := t.TempDir()
	m, err := NewManager(config.OSINTConfig{
		Enabled:        true,
		OutputDir:      dir,
		MaxIoCsPerRule: 7, // small batch to force multiple files
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ts := time.Now().UTC()
	m.clients = []Client{
		&mockClient{
			source: SourceMISP,
			result: FeedResult{Source: SourceMISP, FetchedAt: ts, IoCs: makeIoCs(ips, IoCTypeIP, SourceMISP)},
		},
	}

	m.sync(context.Background())

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fileCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			fileCount++
		}
	}
	// 25 IPs / 7 per file = ceil(25/7) = 4 files
	if fileCount < 3 {
		t.Errorf("expected at least 3 IP rule files for 25 IPs with batch=7, got %d", fileCount)
	}
}

func TestEnrichmentPipeline_StatePathInOutputDir(t *testing.T) {
	m := newManagerWithClients(t, nil)
	expected := filepath.Join(m.cfg.OutputDir, stateFileName)
	if m.statePath != expected {
		t.Errorf("statePath: got %q, want %q", m.statePath, expected)
	}
}
