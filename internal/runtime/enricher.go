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

	// resolver maps an event's in-kernel cgroup id to its container id. When
	// nil, DefaultContainerIDResolver() is used, which is shared with the k8s
	// enricher so the same event resolves /proc at most once (wave 8.1 item 2).
	resolver *ContainerIDResolver

	// pidCache maps PID → container ID (cleared on each TTL tick). It is only
	// consulted for events without a usable CgroupID (0, or the cgroup2 root on v1 hosts), where the
	// cgroup-id resolver cannot help.
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

	return newEnricherWithClient(client, source, cfg, logger), nil
}

// newEnricherWithClient constructs an Enricher from an already-resolved
// RuntimeClient. Used by NewEnricher and directly by tests with stub clients.
func newEnricherWithClient(client RuntimeClient, source string, cfg EnricherConfig, logger *slog.Logger) *Enricher {
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
	}
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
	info := e.lookup(context.Background(), event.CgroupID, event.PID)
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
	info := e.lookup(context.Background(), alert.Event.CgroupID, alert.Event.PID)
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
	// Kubernetes pod identity is carried in the OCI spec annotations
	// (io.kubernetes.pod.*) that the CRI client already collected into
	// src.Labels. Populate it node-locally — no API server required — but never
	// overwrite richer values the k8s enricher may have set earlier in the chain.
	if len(src.Labels) > 0 {
		if dst.Namespace == "" {
			dst.Namespace = src.Labels["io.kubernetes.pod.namespace"]
		}
		if dst.PodName == "" {
			dst.PodName = src.Labels["io.kubernetes.pod.name"]
		}
		if dst.PodUID == "" {
			dst.PodUID = src.Labels["io.kubernetes.pod.uid"]
		}
	}
}

// containerResolver returns the shared cgroup-id resolver, falling back to the
// process-wide default when none was injected.
func (e *Enricher) containerResolver() *ContainerIDResolver {
	if e.resolver != nil {
		return e.resolver
	}
	return DefaultContainerIDResolver()
}

// lookup resolves an event to a ContainerInfo via cgroup → runtime lookup.
//
// When the event carries an in-kernel cgroup id it is resolved through the
// shared cgroup-id resolver: one /proc read per cgroup, with negative (host)
// answers cached. Events from an older BPF object (CgroupID == 0) fall back to
// the pid cache and a single /proc read.
func (e *Enricher) lookup(ctx context.Context, cgroupID uint64, pid uint32) *ContainerInfo {
	// Step 1: resolve event → container ID.
	containerID, err := e.containerID(cgroupID, pid)
	if err != nil || containerID == "" {
		e.missCount.Add(1)
		return nil
	}

	// Step 2: resolve container ID → metadata via cache or runtime query.
	e.containerMu.RLock()
	info, hit := e.containerCache[containerID]
	e.containerMu.RUnlock()

	if hit && time.Since(info.CachedAt) < e.cacheTTL {
		return info
	}

	info, err = e.client.GetContainerInfo(ctx, containerID)
	if err != nil {
		e.logger.Debug("runtime lookup failed, falling back to cgroup container ID",
			slog.String("container_id", containerID[:min(12, len(containerID))]),
			slog.Any("error", err))
		e.missCount.Add(1)
		// Wave 6.1: the metadata query failed, but the cgroup walk above already
		// proved this PID is in a container and produced its ID. Dropping it
		// here reported the process as running on the host, which silently
		// disarmed every rule keyed on container.id. Serve the bare ID instead;
		// name/image stay empty. Cached like any other entry so a broken socket
		// costs one query per TTL rather than one per event, and so recovery is
		// picked up on the next TTL tick.
		info = &ContainerInfo{ContainerID: containerID, CachedAt: time.Now()}
	}

	e.containerMu.Lock()
	e.containerCache[containerID] = info
	e.containerMu.Unlock()

	return info
}

// containerID returns the container id for an event, using the cgroup-id
// resolver when the kernel supplied a cgroup id and the pid fallback otherwise.
func (e *Enricher) containerID(cgroupID uint64, pid uint32) (string, error) {
	if UsableCgroupID(cgroupID) {
		id, _, err := e.containerResolver().Resolve(cgroupID, pid)
		return id, err
	}

	e.pidMu.RLock()
	id, ok := e.pidCache[pid]
	e.pidMu.RUnlock()
	if ok {
		return id, nil
	}

	id, err := extractContainerID(pid)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", ErrNotContainer
	}
	e.pidMu.Lock()
	e.pidCache[pid] = id
	e.pidMu.Unlock()
	return id, nil
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
			// Drop expired cgroup-id entries so pod churn cannot grow the shared
			// resolver's map without bound.
			e.containerResolver().EvictExpired()
		}
	}
}

// updateMetrics pushes the current miss count and cache size to Prometheus.
func (e *Enricher) updateMetrics() {
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

// metricsLoop pushes Prometheus gauges every 15 s.
func (e *Enricher) metricsLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.updateMetrics()
		}
	}
}

// CacheSize returns the number of containers currently held in the metadata cache.
func (e *Enricher) CacheSize() int {
	e.containerMu.RLock()
	defer e.containerMu.RUnlock()
	return len(e.containerCache)
}
