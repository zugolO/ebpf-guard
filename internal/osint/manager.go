package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
)

const stateFileName = ".osint_state.json"

// Manager orchestrates OSINT feed fetching and rule generation.
// It runs periodic syncs and writes generated YAML rules to OutputDir so
// the correlator's hot-reload watcher picks them up automatically.
type Manager struct {
	mu            sync.Mutex // serialises sync() calls from Run ticker and explicit Sync()
	clients       []Client
	generator     *Generator
	cfg           config.OSINTConfig
	statePath     string
	kernelSyncer  *KernelSyncer // optional; nil means no kernel map sync
}

// NewManager creates an OSINT Manager from the provided config.
// Returns nil without error when osint.enabled=false so callers can skip it.
func NewManager(cfg config.OSINTConfig) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	outDir := cfg.OutputDir
	if outDir == "" {
		outDir = "rules/osint"
	}

	var clients []Client

	if cfg.MISP.Enabled {
		if cfg.MISP.URL == "" || cfg.MISP.APIKey == "" {
			return nil, fmt.Errorf("osint: misp enabled but url/api_key not set")
		}
		attrTypes := cfg.MISP.AttributeTypes
		if len(attrTypes) == 0 {
			attrTypes = []string{"ip-dst", "ip-src", "domain", "hostname"}
		}
		clients = append(clients, NewMISPClient(
			cfg.MISP.URL,
			cfg.MISP.APIKey,
			attrTypes,
			cfg.MISP.MinThreatLevel,
			cfg.MISP.Tags,
			cfg.MISP.InsecureSkipVerify,
		))
	}

	if cfg.OpenCTI.Enabled {
		if cfg.OpenCTI.URL == "" || cfg.OpenCTI.APIKey == "" {
			return nil, fmt.Errorf("osint: opencti enabled but url/api_key not set")
		}
		clients = append(clients, NewOpenCTIClient(
			cfg.OpenCTI.URL,
			cfg.OpenCTI.APIKey,
			cfg.OpenCTI.ConfidenceMin,
			cfg.OpenCTI.TLPMarkings,
			cfg.OpenCTI.InsecureSkipVerify,
		))
	}

	if cfg.VirusTotal.Enabled {
		if cfg.VirusTotal.APIKey == "" {
			return nil, fmt.Errorf("osint: virustotal enabled but api_key not set")
		}
		clients = append(clients, NewVirusTotalClient(
			cfg.VirusTotal.APIKey,
			cfg.VirusTotal.EnterpriseFeeds,
		))
	}

	if len(clients) == 0 {
		slog.Warn("osint: enabled but no sources configured — nothing to sync")
	}

	maxPerRule := cfg.MaxIoCsPerRule
	if maxPerRule <= 0 {
		maxPerRule = 500
	}

	return &Manager{
		clients:   clients,
		generator: NewGenerator(outDir, maxPerRule),
		cfg:       cfg,
		statePath: filepath.Join(outDir, stateFileName),
	}, nil
}

// WithKernelSyncer attaches a KernelSyncer so that each feed sync also loads
// IP/CIDR IoCs into kernel BPF maps. Call before Run(). Passing nil is a
// no-op (kernel sync remains disabled).
func (m *Manager) WithKernelSyncer(ks *KernelSyncer) *Manager {
	if m == nil {
		return m
	}
	m.kernelSyncer = ks
	return m
}

// Run starts the OSINT sync loop. It performs an initial sync immediately,
// then repeats at the configured interval. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	if m == nil {
		return nil
	}

	interval := 3 * time.Hour
	if m.cfg.RefreshInterval != "" {
		d, err := time.ParseDuration(m.cfg.RefreshInterval)
		if err != nil {
			return fmt.Errorf("osint: invalid refresh_interval %q: %w", m.cfg.RefreshInterval, err)
		}
		interval = d
	}

	// Run immediately on startup.
	m.sync(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.sync(ctx)
		}
	}
}

// Sync triggers an immediate synchronization with all configured OSINT sources.
// Safe to call concurrently; each call serialises internally via the manager.
func (m *Manager) Sync(ctx context.Context) {
	if m == nil {
		return
	}
	m.sync(ctx)
}

func (m *Manager) sync(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.loadState()

	successfulResults := make([]FeedResult, 0, len(m.clients))

	for _, client := range m.clients {
		select {
		case <-ctx.Done():
			return
		default:
		}

		src := client.Source()
		since := state.LastSync[src]
		slog.Info("osint: fetching feed", slog.String("source", string(src)), slog.Time("since", since))

		result, err := client.Fetch(since)
		if err != nil {
			slog.Error("osint: fetch failed", slog.String("source", string(src)), slog.Any("error", err))
			continue
		}

		slog.Info("osint: fetched IoCs", slog.String("source", string(src)), slog.Int("count", len(result.IoCs)))

		fileMap, err := m.generator.GenerateRules(result)
		if err != nil {
			slog.Error("osint: rule generation failed", slog.String("source", string(src)), slog.Any("error", err))
			continue
		}

		slog.Info("osint: rules written", slog.String("source", string(src)), slog.Int("files", len(fileMap)))

		state.LastSync[src] = result.FetchedAt
		for k, v := range fileMap {
			state.RuleFiles[k] = v
		}
		successfulResults = append(successfulResults, result)
	}

	// Load IP/CIDR IoCs into kernel maps after all feeds are fetched.
	if m.kernelSyncer != nil && len(successfulResults) > 0 {
		n, err := m.kernelSyncer.SyncToKernel(successfulResults)
		if err != nil {
			slog.Warn("osint: kernel map sync partial failure", slog.Any("error", err), slog.Int("active", n))
		} else {
			slog.Info("osint: kernel map sync complete", slog.Int("active", n))
		}
	}

	m.saveState(state)
}

func (m *Manager) loadState() SyncState {
	state := SyncState{
		LastSync:  make(map[Source]time.Time),
		RuleFiles: make(map[string]string),
	}
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		return state // First run or missing state file — normal.
	}
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Warn("osint: state file corrupt, starting fresh", slog.Any("error", err))
		return SyncState{
			LastSync:  make(map[Source]time.Time),
			RuleFiles: make(map[string]string),
		}
	}
	if state.LastSync == nil {
		state.LastSync = make(map[Source]time.Time)
	}
	if state.RuleFiles == nil {
		state.RuleFiles = make(map[string]string)
	}
	return state
}

func (m *Manager) saveState(state SyncState) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		slog.Error("osint: marshal state", slog.Any("error", err))
		return
	}
	if err := os.WriteFile(m.statePath, data, 0o600); err != nil {
		slog.Error("osint: write state", slog.Any("error", err))
	}
}
