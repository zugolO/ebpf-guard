// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// AlertAggregator batches similar alerts to reduce noise.
type AlertAggregator struct {
	window      time.Duration
	maxSamples  int
	
	mu       sync.RWMutex
	buckets  map[string]*alertBucket
}

// alertBucket holds aggregated alerts for a specific rule/PID combination.
type alertBucket struct {
	key        string
	ruleID     string
	severity   types.AlertSeverity
	summary    string
	firstSeen  time.Time
	lastSeen   time.Time
	count      int
	samples    []types.Alert
	maxSamples int
	mu         sync.Mutex
}

// NewAlertAggregator creates a new alert aggregator.
func NewAlertAggregator(window time.Duration, maxSamples int) *AlertAggregator {
	return &AlertAggregator{
		window:     window,
		maxSamples: maxSamples,
		buckets:    make(map[string]*alertBucket),
	}
}

// Add adds an alert to the aggregator. Returns true if a new bucket was created.
func (a *AlertAggregator) Add(alert types.Alert) bool {
	key := a.makeKey(alert)
	
	a.mu.RLock()
	bucket, exists := a.buckets[key]
	a.mu.RUnlock()
	
	if exists {
		bucket.add(alert)
		return false
	}
	
	a.mu.Lock()
	defer a.mu.Unlock()
	
	// Double-check after acquiring write lock
	if bucket, exists = a.buckets[key]; exists {
		bucket.add(alert)
		return false
	}
	
	// Create new bucket
	bucket = &alertBucket{
		key:        key,
		ruleID:     alert.RuleID,
		severity:   alert.Severity,
		summary:    alert.RuleName,
		firstSeen:  time.Now(),
		lastSeen:   time.Now(),
		count:      1,
		samples:    []types.Alert{alert},
		maxSamples: a.maxSamples,
	}
	a.buckets[key] = bucket
	
	return true
}

// Flush returns all buckets that have exceeded the aggregation window.
func (a *AlertAggregator) Flush() []types.Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	now := time.Now()
	var results []types.Alert
	
	for key, bucket := range a.buckets {
		if now.Sub(bucket.lastSeen) > a.window {
			// Bucket has expired, create aggregated alert
			aggAlert := bucket.toAlert()
			results = append(results, aggAlert)
			delete(a.buckets, key)
		}
	}
	
	return results
}

// GetAll returns all current buckets as alerts (for shutdown).
func (a *AlertAggregator) GetAll() []types.Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	var results []types.Alert
	for _, bucket := range a.buckets {
		results = append(results, bucket.toAlert())
	}
	a.buckets = make(map[string]*alertBucket)
	return results
}

// makeKey creates an aggregation key from an alert.
// Alerts with the same rule and PID are aggregated together.
func (a *AlertAggregator) makeKey(alert types.Alert) string {
	return fmt.Sprintf("%s:%d", alert.RuleID, alert.Event.PID)
}

// add adds an alert to the bucket.
func (b *alertBucket) add(alert types.Alert) {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	b.lastSeen = time.Now()
	b.count++
	
	if len(b.samples) < b.maxSamples {
		b.samples = append(b.samples, alert)
	}
}

// toAlert converts the bucket to an aggregated alert.
func (b *alertBucket) toAlert() types.Alert {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	description := fmt.Sprintf("%s (occurred %d times)", b.summary, b.count)
	if b.count > 1 {
		duration := b.lastSeen.Sub(b.firstSeen)
		description = fmt.Sprintf("%s over %s", description, duration.Round(time.Second))
	}
	
	var sampleEvent types.Event
	if len(b.samples) > 0 {
		sampleEvent = b.samples[0].Event
	}
	
	return types.Alert{
		ID:        b.ruleID + "-" + strconv.FormatInt(b.lastSeen.UnixNano(), 10),
		Timestamp: b.lastSeen,
		RuleID:    b.ruleID,
		RuleName:  b.summary,
		Severity:  b.severity,
		Message:   description,
		Event:     sampleEvent,
	}
}

// Start begins the background cleanup goroutine.
func (a *AlertAggregator) Start(ctx context.Context) {
	ticker := time.NewTicker(a.window / 2)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flushed := a.Flush()
			if len(flushed) > 0 {
				slog.Debug("exporter/aggregator: flushed aggregated alerts",
					slog.Int("count", len(flushed)))
			}
		}
	}
}
