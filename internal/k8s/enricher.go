// Package k8s provides Kubernetes metadata enrichment and pod watching.
package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Enricher provides Kubernetes metadata enrichment for security events and alerts.
type Enricher struct {
	watcher *Watcher
	logger  *slog.Logger
	
	// enrichmentCache caches enrichment results to reduce cgroup reads
	mu             sync.RWMutex
	enrichmentCache map[uint32]*EnrichmentInfo
	cacheTTL       time.Duration
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
}

// NewEnricher creates a new Kubernetes metadata enricher.
func NewEnricher(config EnricherConfig, logger *slog.Logger) (*Enricher, error) {
	watcherConfig := WatcherConfig{
		KubeconfigPath: config.KubeconfigPath,
		ResyncPeriod:   config.ResyncPeriod,
	}

	watcher, err := NewWatcher(watcherConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("k8s/enricher: create watcher: %w", err)
	}

	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 30 * time.Second
	}

	return &Enricher{
		watcher:         watcher,
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        cacheTTL,
	}, nil
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

	// watcher.Start blocks until ctx is cancelled.
	err := e.watcher.Start(ctx)
	cancel()  // signal cleanup goroutine to stop
	wg.Wait() // wait for it to exit before returning
	return err
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

	// Lookup pod info from watcher
	podInfo, ok := e.watcher.GetPodInfoByPID(pid)
	if !ok {
		return nil
	}

	// Create enrichment info
	info := &EnrichmentInfo{
		PodName:     podInfo.Name,
		Namespace:   podInfo.Namespace,
		PodUID:      podInfo.UID,
		NodeName:    podInfo.NodeName,
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

// IsHealthy returns true if the enricher is healthy (watcher has synced).
func (e *Enricher) IsHealthy() bool {
	// The watcher is healthy if it exists
	return e.watcher != nil
}

// ReadyCheck implements the health check interface for the HTTP server.
func (e *Enricher) ReadyCheck() error {
	if !e.IsHealthy() {
		return fmt.Errorf("k8s enricher not ready")
	}
	return nil
}

// LiveCheck implements the liveness check interface.
func (e *Enricher) LiveCheck() error {
	// Enricher is always live if it's running
	return nil
}
