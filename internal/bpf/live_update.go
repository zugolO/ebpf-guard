package bpf

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
)

// ProgramLink abstracts an attached eBPF program link so it can be atomically replaced.
// The concrete implementation is *link.Link from github.com/cilium/ebpf/link.
type ProgramLink interface {
	// Update atomically replaces the attached eBPF program without detaching.
	Update(new *ebpf.Program) error
	// Close detaches and releases the link.
	Close() error
}

// CollectionLoader loads a new ebpf.Collection from a specification.
// Separating this into an interface makes the LiveUpdater unit-testable.
type CollectionLoader interface {
	// Load verifies and loads newSpec into the kernel. The returned collection
	// must be closed by the caller when no longer needed.
	Load(newSpec *ebpf.CollectionSpec) (*ebpf.Collection, error)
}

// defaultCollectionLoader is the production implementation backed by cilium/ebpf.
type defaultCollectionLoader struct{}

func (defaultCollectionLoader) Load(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	return ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
}

// LiveUpdater performs in-place eBPF program replacement without detaching links.
// Programs are atomically swapped via link.Update(); in-flight events are drained
// before replacement to stay within the 100 ms pause budget.
//
// Usage:
//
//	lu := NewLiveUpdater(logger, nil)
//	lu.RegisterLink("sys_enter", myLink)
//	lu.Reload(ctx, "/etc/ebpf-guard/bpf/syscall.bpf.o")
type LiveUpdater struct {
	mu     sync.RWMutex
	logger *slog.Logger
	loader CollectionLoader

	// attachedLinks maps BPF program name → the live link for that program.
	attachedLinks map[string]ProgramLink
	// currentColl is the active ebpf.Collection; replaced on every successful LiveUpdate.
	currentColl *ebpf.Collection

	// pendingPinDir is the bpffs directory used to stage new programs before swapping.
	pendingPinDir string

	// watchPath is the directory watched for .o file changes (fsnotify).
	watchPath string
	// watcher is the optional fsnotify watcher for bpf object files.
	watcher    *fsnotify.Watcher
	stopWatch  context.CancelFunc

	// Prometheus metrics.
	updatesTotal prometheus.Counter
	errorsTotal  prometheus.Counter
}

// LiveUpdateConfig holds optional configuration for LiveUpdater.
type LiveUpdateConfig struct {
	// PendingPinDir is the bpffs path used to pin new programs during staging.
	// Defaults to /sys/fs/bpf/ebpf-guard/pending.
	PendingPinDir string
	// WatchPath is the directory watched for updated .o files (fsnotify).
	// Empty disables file watching.
	WatchPath string
	// Loader overrides the default ebpf.Collection loader (used in tests).
	Loader CollectionLoader
	// OnReload is called after every successful live update (may be nil).
	OnReload func()
}

// NewLiveUpdater creates a LiveUpdater. Call RegisterLink for each attached
// program before the first Reload.
func NewLiveUpdater(logger *slog.Logger, cfg LiveUpdateConfig) *LiveUpdater {
	if cfg.PendingPinDir == "" {
		cfg.PendingPinDir = "/sys/fs/bpf/ebpf-guard/pending"
	}
	ldr := cfg.Loader
	if ldr == nil {
		ldr = defaultCollectionLoader{}
	}
	lu := &LiveUpdater{
		logger:        logger.With("component", "bpf_live_updater"),
		loader:        ldr,
		attachedLinks: make(map[string]ProgramLink),
		pendingPinDir: cfg.PendingPinDir,
		watchPath:     cfg.WatchPath,
		updatesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_live_updates_total",
			Help: "Total successful eBPF live program replacements.",
		}),
		errorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_live_update_errors_total",
			Help: "Total eBPF live update failures (rollback attempted on each).",
		}),
	}
	return lu
}

// RegisterMetrics registers the live-update Prometheus metrics.
func (lu *LiveUpdater) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{lu.updatesTotal, lu.errorsTotal} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// RegisterLink records the live link for a named BPF program so it can be
// replaced atomically by LiveUpdate. Must be called before the first reload.
func (lu *LiveUpdater) RegisterLink(name string, link ProgramLink) {
	lu.mu.Lock()
	defer lu.mu.Unlock()
	lu.attachedLinks[name] = link
}

// SetCurrentCollection sets the initial active collection.
// Call this after the agent's initial BPF load so LiveUpdate can close it.
func (lu *LiveUpdater) SetCurrentCollection(coll *ebpf.Collection) {
	lu.mu.Lock()
	defer lu.mu.Unlock()
	lu.currentColl = coll
}

// Reload loads a new BPF object file at path and atomically replaces all
// programs whose names match a registered link.
func (lu *LiveUpdater) Reload(ctx context.Context, path string) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("bpf/live_update: load spec %s: %w", path, err)
	}
	return lu.LiveUpdate(ctx, spec)
}

// LiveUpdate atomically replaces eBPF programs using the given CollectionSpec.
//
// Steps:
//  1. Load (verify) new programs into the kernel.
//  2. Pin them to pendingPinDir for visibility.
//  3. Drain in-flight events (≤100 ms pause).
//  4. Atomically swap each attached link via link.Update().
//  5. On partial failure, roll back all successfully swapped links.
//  6. Release the previous collection.
func (lu *LiveUpdater) LiveUpdate(ctx context.Context, newSpec *ebpf.CollectionSpec) error {
	lu.mu.Lock()
	defer lu.mu.Unlock()

	// 1. Load new collection (verifies BPF bytecode in the kernel verifier).
	newColl, err := lu.loader.Load(newSpec)
	if err != nil {
		lu.errorsTotal.Inc()
		return fmt.Errorf("bpf/live_update: load collection: %w", err)
	}

	// 2. Pin new programs to bpffs staging directory.
	if err := os.MkdirAll(lu.pendingPinDir, 0700); err != nil {
		newColl.Close()
		lu.errorsTotal.Inc()
		return fmt.Errorf("bpf/live_update: mkdir pending pin dir: %w", err)
	}
	for name, prog := range newColl.Programs {
		if prog == nil {
			continue
		}
		pinPath := filepath.Join(lu.pendingPinDir, name)
		if err := prog.Pin(pinPath); err != nil {
			// Non-fatal: pinning is best-effort for observability.
			lu.logger.Warn("failed to pin pending program", slog.String("name", name), slog.Any("error", err))
		}
	}

	// 3. Brief drain: give in-flight ring-buffer consumers time to finish.
	drainCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	lu.drainInFlight(drainCtx)

	// 4. Atomically swap each program that has a registered link.
	var swapped []string
	for name, link := range lu.attachedLinks {
		newProg, ok := newColl.Programs[name]
		if !ok {
			lu.logger.Debug("no program in new collection for link; skipping", slog.String("name", name))
			continue
		}
		if err := link.Update(newProg); err != nil {
			// 5. Rollback: restore previous programs on all already-swapped links.
			lu.rollback(swapped, newColl)
			newColl.Close()
			lu.errorsTotal.Inc()
			return fmt.Errorf("bpf/live_update: update link %s: %w (rolled back)", name, err)
		}
		swapped = append(swapped, name)
	}

	// 6. Release the old collection.
	if lu.currentColl != nil {
		lu.currentColl.Close()
	}
	lu.currentColl = newColl

	// Remove staging pins (cleanup; ignore errors).
	for _, name := range swapped {
		_ = os.Remove(filepath.Join(lu.pendingPinDir, name))
	}

	lu.updatesTotal.Inc()
	lu.logger.Info("eBPF live update successful",
		slog.Int("programs_updated", len(swapped)),
	)
	return nil
}

// rollback restores the previous programs on links that were already swapped.
// It uses the old programs still loaded in currentColl.
func (lu *LiveUpdater) rollback(swapped []string, failedColl *ebpf.Collection) {
	if lu.currentColl == nil {
		return
	}
	for _, name := range swapped {
		oldProg, ok := lu.currentColl.Programs[name]
		if !ok {
			continue
		}
		if link, ok := lu.attachedLinks[name]; ok {
			if err := link.Update(oldProg); err != nil {
				lu.logger.Error("rollback failed for program",
					slog.String("name", name),
					slog.Any("error", err),
				)
			}
		}
	}
	lu.logger.Warn("eBPF live update rolled back", slog.Int("programs_restored", len(swapped)))
}

// drainInFlight waits for a short window to let in-flight BPF→userspace events
// reach the ring-buffer consumer goroutines before program replacement.
func (lu *LiveUpdater) drainInFlight(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Millisecond):
	}
}

// StartFileWatcher starts an fsnotify watcher on WatchPath and calls Reload
// automatically when any .o file changes. Returns immediately if WatchPath is empty.
func (lu *LiveUpdater) StartFileWatcher(ctx context.Context) error {
	if lu.watchPath == "" {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("bpf/live_update: create watcher: %w", err)
	}
	if err := watcher.Add(lu.watchPath); err != nil {
		watcher.Close()
		return fmt.Errorf("bpf/live_update: watch %s: %w", lu.watchPath, err)
	}

	watchCtx, cancel := context.WithCancel(ctx)
	lu.mu.Lock()
	lu.watcher = watcher
	lu.stopWatch = cancel
	lu.mu.Unlock()

	go lu.watchLoop(watchCtx, watcher)
	lu.logger.Info("eBPF file watcher started", slog.String("path", lu.watchPath))
	return nil
}

func (lu *LiveUpdater) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) {
	for {
		select {
		case <-ctx.Done():
			watcher.Close()
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if filepath.Ext(event.Name) != ".o" {
					continue
				}
				lu.logger.Info("BPF object file changed; triggering live update",
					slog.String("file", event.Name))
				if err := lu.Reload(ctx, event.Name); err != nil {
					lu.logger.Error("live update from file watcher failed",
						slog.String("file", event.Name),
						slog.Any("error", err))
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			lu.logger.Warn("file watcher error", slog.Any("error", err))
		}
	}
}

// Close stops the file watcher and releases resources.
// The currentColl is NOT closed here; the caller owns that lifetime.
func (lu *LiveUpdater) Close() {
	lu.mu.Lock()
	defer lu.mu.Unlock()
	if lu.stopWatch != nil {
		lu.stopWatch()
		lu.stopWatch = nil
	}
}

// UpdatesTotal returns the total number of successful live updates.
func (lu *LiveUpdater) UpdatesTotal() prometheus.Counter { return lu.updatesTotal }

// ErrorsTotal returns the total number of live update errors.
func (lu *LiveUpdater) ErrorsTotal() prometheus.Counter { return lu.errorsTotal }
