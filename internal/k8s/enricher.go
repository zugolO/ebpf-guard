// Package k8s provides Kubernetes metadata enrichment and pod watching.
package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// EnricherMetrics holds optional Prometheus instruments wired in by the caller.
// Any nil field is silently ignored.
type EnricherMetrics struct {
	// CachePods tracks the current number of unique pods in the watcher cache.
	CachePods prometheus.Gauge
	// CacheStaleness tracks how many seconds have elapsed since the last watcher sync.
	CacheStaleness prometheus.Gauge
	// LastSync records the Unix timestamp (seconds) of the last watcher sync.
	LastSync prometheus.Gauge
	// MissTotal counts enrichment lookups that found no matching pod.
	MissTotal prometheus.Counter
}

// Enricher provides Kubernetes metadata enrichment for security events and alerts.
type Enricher struct {
	watcher      *Watcher
	logger       *slog.Logger
	resyncPeriod time.Duration

	// enrichmentCache caches enrichment results to reduce cgroup reads
	mu              sync.RWMutex
	enrichmentCache map[uint32]*EnrichmentInfo
	cacheTTL        time.Duration

	// missCount is the number of enrichment lookups that found no pod.
	// Exported to a Prometheus counter via the metrics update loop.
	missCount atomic.Int64

	metrics EnricherMetrics
}

// EnrichmentInfo contains Kubernetes metadata attached to events/alerts.
type EnrichmentInfo struct {
	PodName       string
	Namespace     string
	PodUID        string
	NodeName      string
	Labels        map[string]string
	Annotations   map[string]string
	ContainerID   string
	CachedAt      time.Time
}

// EnricherConfig holds configuration for the enricher.
type EnricherConfig struct {
	KubeconfigPath string
	ResyncPeriod   time.Duration
	CacheTTL       time.Duration
	// NodeName scopes pod watching to a single node. Empty falls back to the
	// NODE_NAME env var, then to watching all cluster pods.
	NodeName string
	// Metrics provides optional Prometheus instruments for observability.
	// All fields are optional — nil values are silently skipped.
	Metrics EnricherMetrics
}

// NewEnricher creates a new Kubernetes metadata enricher.
func NewEnricher(config EnricherConfig, logger *slog.Logger) (*Enricher, error) {
	watcherConfig := WatcherConfig{
		KubeconfigPath: config.KubeconfigPath,
		ResyncPeriod:   config.ResyncPeriod,
		NodeName:       config.NodeName,
	}

	watcher, err := NewWatcher(watcherConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("k8s/enricher: create watcher: %w", err)
	}

	return newEnricherWithWatcher(watcher, config, logger), nil
}

// newEnricherWithWatcher builds an Enricher from a pre-built Watcher.
// Extracted from NewEnricher so tests can inject a test watcher without
// requiring a real kubeconfig.
func newEnricherWithWatcher(watcher *Watcher, config EnricherConfig, logger *slog.Logger) *Enricher {
	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 30 * time.Second
	}

	resyncPeriod := config.ResyncPeriod
	if resyncPeriod == 0 {
		resyncPeriod = 300 * time.Second
	}

	return &Enricher{
		watcher:         watcher,
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        cacheTTL,
		resyncPeriod:    resyncPeriod,
		metrics:         config.Metrics,
	}
}

// Start begins the enricher and its watcher.
func (e *Enricher) Start(ctx context.Context) error {
	e.logger.Info("starting k8s enricher")

	cleanupCtx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.cacheCleanupLoop(cleanupCtx)
	}()

	if e.hasMetrics() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.metricsUpdateLoop(cleanupCtx)
		}()
	}

	// watcher.Start blocks until ctx is cancelled.
	err := e.watcher.Start(ctx)
	cancel()  // signal goroutines to stop
	wg.Wait() // wait for them to exit before returning
	return err
}

// hasMetrics returns true if any Prometheus metric is configured.
func (e *Enricher) hasMetrics() bool {
	return e.metrics.CachePods != nil ||
		e.metrics.CacheStaleness != nil ||
		e.metrics.LastSync != nil ||
		e.metrics.MissTotal != nil
}

// metricsUpdateLoop periodically refreshes gauge metrics from the watcher.
func (e *Enricher) metricsUpdateLoop(ctx context.Context) {
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

// updateMetrics pushes current enricher state to Prometheus.
func (e *Enricher) updateMetrics() {
	// Always drain accumulated miss count regardless of watcher state.
	if e.metrics.MissTotal != nil {
		if n := e.missCount.Swap(0); n > 0 {
			e.metrics.MissTotal.Add(float64(n))
		}
	}

	if e.watcher == nil {
		return
	}

	if e.metrics.CachePods != nil {
		e.metrics.CachePods.Set(float64(e.watcher.CachePodCount()))
	}

	lastSync := e.watcher.LastSyncAt()
	if !lastSync.IsZero() {
		if e.metrics.LastSync != nil {
			e.metrics.LastSync.Set(float64(lastSync.Unix()))
		}
		if e.metrics.CacheStaleness != nil {
			e.metrics.CacheStaleness.Set(time.Since(lastSync).Seconds())
		}
	}
}

// Stop stops the enricher.
func (e *Enricher) Stop() error {
	e.logger.Info("stopping k8s enricher")
	return e.watcher.Stop()
}

// EnrichEvent adds Kubernetes metadata to an event.
func (e *Enricher) EnrichEvent(event *types.Event) {
	if event == nil {
		return
	}

	info := e.getEnrichmentInfo(event.PID)
	if info == nil {
		return
	}

	// Convert internal EnrichmentInfo to types.EnrichmentInfo
	event.Enrichment = info.ToTypesEnrichment()
}

// EnrichAlert adds Kubernetes metadata to an alert.
func (e *Enricher) EnrichAlert(alert *types.Alert) {
	if alert == nil {
		return
	}

	info := e.getEnrichmentInfo(alert.Event.PID)
	if info == nil {
		return
	}

	// Update alert with Kubernetes metadata
	typesInfo := info.ToTypesEnrichment()
	if typesInfo != nil {
		alert.Enrichment = *typesInfo
	}
}

// getEnrichmentInfo gets or creates enrichment info for a PID.
func (e *Enricher) getEnrichmentInfo(pid uint32) *EnrichmentInfo {
	// Check cache first
	e.mu.RLock()
	if info, ok := e.enrichmentCache[pid]; ok {
		if time.Since(info.CachedAt) < e.cacheTTL {
			e.mu.RUnlock()
			return info
		}
	}
	e.mu.RUnlock()

	// Lookup pod info from watcher (nil watcher = enricher not yet started)
	if e.watcher == nil {
		e.missCount.Add(1)
		return nil
	}
	podInfo, ok := e.watcher.GetPodInfoByPID(pid)
	if !ok {
		e.missCount.Add(1)
		return nil
	}

	// Create enrichment info. Intern high-repetition strings (namespace, node
	// name) so events sharing the same metadata share the same string pointer,
	// reducing GC pressure on long-running DaemonSet deployments.
	info := &EnrichmentInfo{
		PodName:     podInfo.Name,
		Namespace:   util.InternString(podInfo.Namespace),
		PodUID:      podInfo.UID,
		NodeName:    util.InternString(podInfo.NodeName),
		Labels:      copyMap(podInfo.Labels),
		Annotations: copyMap(podInfo.Annotations),
		CachedAt:    time.Now(),
	}

	// Cache the result. Re-check under the write lock: another goroutine may
	// have populated a fresh entry while we were calling GetPodInfoByPID.
	// If so, prefer the existing entry to avoid overwriting more-recent data.
	e.mu.Lock()
	if existing, ok := e.enrichmentCache[pid]; ok && time.Since(existing.CachedAt) < e.cacheTTL {
		info = existing
	} else {
		e.enrichmentCache[pid] = info
	}
	e.mu.Unlock()

	return info
}

// GetEnrichmentInfo returns Kubernetes metadata for a given PID.
func (e *Enricher) GetEnrichmentInfo(pid uint32) (*EnrichmentInfo, bool) {
	info := e.getEnrichmentInfo(pid)
	if info == nil {
		return nil, false
	}
	return info, true
}

// ToTypesEnrichment converts internal EnrichmentInfo to types.EnrichmentInfo.
func (ei *EnrichmentInfo) ToTypesEnrichment() *types.EnrichmentInfo {
	if ei == nil {
		return nil
	}
	return &types.EnrichmentInfo{
		PodName:     ei.PodName,
		Namespace:   ei.Namespace,
		PodUID:      ei.PodUID,
		NodeName:    ei.NodeName,
		Labels:      copyMap(ei.Labels),
		Annotations: copyMap(ei.Annotations),
		ContainerID: ei.ContainerID,
	}
}

// GetPodInfo returns raw pod info for a given PID (for advanced use cases).
func (e *Enricher) GetPodInfo(pid uint32) (*PodInfo, bool) {
	return e.watcher.GetPodInfoByPID(pid)
}

// cacheCleanupLoop periodically cleans up expired cache entries.
func (e *Enricher) cacheCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(e.cacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.cleanupCache()
		}
	}
}

// cleanupCache removes expired entries from the enrichment cache.
func (e *Enricher) cleanupCache() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	for pid, info := range e.enrichmentCache {
		if now.Sub(info.CachedAt) > e.cacheTTL {
			delete(e.enrichmentCache, pid)
		}
	}
}

// GetCachedPodCount returns the number of pods in the watcher cache.
func (e *Enricher) GetCachedPodCount() int {
	return len(e.watcher.GetAllPods())
}

// IsHealthy returns true if the enricher's watcher exists and has completed its
// initial cache sync.
func (e *Enricher) IsHealthy() bool {
	return e.watcher != nil && e.watcher.HasSynced()
}

// ReadyCheck implements the health check interface for the HTTP server.
// Returns an error when:
//   - the watcher has not completed its initial sync yet, or
//   - the last sync is older than 2× the configured resync period (cache stale).
func (e *Enricher) ReadyCheck() error {
	if e.watcher == nil {
		return fmt.Errorf("k8s enricher not ready: watcher not initialised")
	}
	lastSync := e.watcher.LastSyncAt()
	if lastSync.IsZero() {
		return fmt.Errorf("k8s enricher not ready: initial cache sync not completed")
	}
	staleness := time.Since(lastSync)
	maxStaleness := 2 * e.resyncPeriod
	if staleness > maxStaleness {
		return fmt.Errorf("k8s enricher cache stale: last sync %v ago (threshold %v)",
			staleness.Round(time.Second), maxStaleness)
	}
	return nil
}

// LiveCheck implements the liveness check interface.
func (e *Enricher) LiveCheck() error {
	// Enricher is always live if it's running
	return nil
}
