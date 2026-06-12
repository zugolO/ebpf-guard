package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// EnricherMetrics holds optional Prometheus instruments wired in by the caller.
// Any nil field is silently ignored.
type EnricherMetrics struct {
	// CacheSize tracks the current number of unique containers in the metadata cache.
	CacheSize prometheus.Gauge
	// MissTotal counts enrichment lookups that found no container metadata.
	MissTotal prometheus.Counter
}

// EnricherConfig configures the runtime enricher.
type EnricherConfig struct {
	// Mode is "auto", "cri", "docker", or "off".
	// "auto" tries CRI first, then Docker.
	Mode string
	// SocketPath overrides socket auto-detection when non-empty.
	SocketPath string
	// CacheTTL controls how long container metadata is cached. Default: 30s.
	CacheTTL time.Duration
	// Metrics provides optional Prometheus instruments. All fields are optional.
	Metrics EnricherMetrics
}

// Enricher resolves container metadata (name, image, labels) from the container
// runtime and attaches it to events and alerts. It maps PID → container ID via
// /proc/[pid]/cgroup, then queries the runtime for container-level metadata.
type Enricher struct {
	client   RuntimeClient
	source   string // "docker", "containerd", or "crio"
	logger   *slog.Logger
	cacheTTL time.Duration
	metrics  EnricherMetrics

	// pidCache maps PID → container ID (cleared on each TTL tick).
	pidMu    sync.RWMutex
	pidCache map[uint32]string

	// containerCache maps container ID → ContainerInfo with TTL check on read.
	containerMu    sync.RWMutex
	containerCache map[string]*ContainerInfo

	missCount atomic.Int64
}

// NewEnricher creates a new container runtime enricher.
// Returns an error when Mode is "off" or no runtime is available.
func NewEnricher(cfg EnricherConfig, logger *slog.Logger) (*Enricher, error) {
	if cfg.Mode == "off" || cfg.Mode == "" {
		return nil, fmt.Errorf("runtime enrichment is disabled (mode=%q)", cfg.Mode)
	}

	var (
		client RuntimeClient
		source string
		err    error
	)
	switch cfg.Mode {
	case "docker":
		client, err = newDockerClient(cfg.SocketPath)
		source = "docker"
	case "cri":
		c, criErr := newCRIClient(cfg.SocketPath)
		if criErr != nil {
			return nil, fmt.Errorf("runtime/cri: %w", criErr)
		}
		client, source = c, c.runtimeType
	default: // "auto"
		client, source, err = autoDetect(cfg.SocketPath)
	}
	if err != nil {
		return nil, fmt.Errorf("runtime enricher: %w", err)
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}

	return &Enricher{
		client:         client,
		source:         source,
		logger:         logger.With("component", "runtime_enricher", "source", source),
		cacheTTL:       cacheTTL,
		metrics:        cfg.Metrics,
		pidCache:       make(map[uint32]string),
		containerCache: make(map[string]*ContainerInfo),
	}, nil
}

// Start runs background cache-cleanup and metrics loops until ctx is cancelled.
// It does not block; callers should call it in a goroutine alongside the agent loop.
func (e *Enricher) Start(ctx context.Context) {
	e.logger.Info("runtime enricher started")
	go e.cleanupLoop(ctx)
	if e.metrics.CacheSize != nil || e.metrics.MissTotal != nil {
		go e.metricsLoop(ctx)
	}
}

// Stop releases the runtime client connection.
func (e *Enricher) Stop() error {
	e.logger.Info("runtime enricher stopped")
	return e.client.Close()
}

// EnrichEvent adds container runtime metadata to an event.
// It is safe to call concurrently from multiple goroutines.
func (e *Enricher) EnrichEvent(event *types.Event) {
	if event == nil {
		return
	}
	info := e.lookupByPID(context.Background(), event.PID)
	if info == nil {
		return
	}
	if event.Enrichment == nil {
		event.Enrichment = &types.EnrichmentInfo{}
	}
	applyTo(event.Enrichment, info, e.source)
}

// EnrichAlert adds container runtime metadata to an alert.
func (e *Enricher) EnrichAlert(alert *types.Alert) {
	if alert == nil {
		return
	}
	info := e.lookupByPID(context.Background(), alert.Event.PID)
	if info == nil {
		return
	}
	applyTo(&alert.Enrichment, info, e.source)
}

// Source returns the runtime that was detected ("docker", "containerd", "crio").
func (e *Enricher) Source() string { return e.source }

// applyTo copies the container metadata from ContainerInfo into an EnrichmentInfo,
// preserving any Kubernetes fields already set by the k8s enricher.
func applyTo(dst *types.EnrichmentInfo, src *ContainerInfo, source string) {
	if dst.ContainerID == "" {
		dst.ContainerID = src.ContainerID
	}
	if dst.ContainerName == "" {
		dst.ContainerName = src.ContainerName
	}
	if dst.ContainerImage == "" {
		dst.ContainerImage = src.Image
	}
	if dst.RuntimeSource == "" {
		dst.RuntimeSource = source
	}
}

// lookupByPID resolves a PID to a ContainerInfo via cgroup → runtime lookup.
func (e *Enricher) lookupByPID(ctx context.Context, pid uint32) *ContainerInfo {
	// Step 1: resolve PID → container ID via /proc/[pid]/cgroup.
	e.pidMu.RLock()
	containerID, ok := e.pidCache[pid]
	e.pidMu.RUnlock()

	if !ok {
		var err error
		containerID, err = extractContainerID(pid)
		if err != nil || containerID == "" {
			e.missCount.Add(1)
			return nil
		}
		e.pidMu.Lock()
		e.pidCache[pid] = containerID
		e.pidMu.Unlock()
	}

	// Step 2: resolve container ID → metadata via cache or runtime query.
	e.containerMu.RLock()
	info, hit := e.containerCache[containerID]
	e.containerMu.RUnlock()

	if hit && time.Since(info.CachedAt) < e.cacheTTL {
		return info
	}

	info, err := e.client.GetContainerInfo(ctx, containerID)
	if err != nil {
		e.logger.Debug("runtime lookup failed",
			slog.String("container_id", containerID[:min(12, len(containerID))]),
			slog.Any("error", err))
		e.missCount.Add(1)
		return nil
	}

	e.containerMu.Lock()
	e.containerCache[containerID] = info
	e.containerMu.Unlock()

	return info
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cleanupLoop periodically evicts expired entries from both caches.
func (e *Enricher) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(e.cacheTTL)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			e.containerMu.Lock()
			for id, info := range e.containerCache {
				if now.Sub(info.CachedAt) > e.cacheTTL {
					delete(e.containerCache, id)
				}
			}
			e.containerMu.Unlock()
			// PID → container ID mapping has no timestamp; flush on TTL interval.
			e.pidMu.Lock()
			e.pidCache = make(map[uint32]string)
			e.pidMu.Unlock()
		}
	}
}

// metricsLoop pushes Prometheus gauges every 15 s.
func (e *Enricher) metricsLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if e.metrics.MissTotal != nil {
				if n := e.missCount.Swap(0); n > 0 {
					e.metrics.MissTotal.Add(float64(n))
				}
			}
			if e.metrics.CacheSize != nil {
				e.containerMu.RLock()
				size := len(e.containerCache)
				e.containerMu.RUnlock()
				e.metrics.CacheSize.Set(float64(size))
			}
		}
	}
}

// CacheSize returns the number of containers currently held in the metadata cache.
func (e *Enricher) CacheSize() int {
	e.containerMu.RLock()
	defer e.containerMu.RUnlock()
	return len(e.containerCache)
}
