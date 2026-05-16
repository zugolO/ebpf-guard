# Lock Ordering Reference

This document describes all mutex acquisition orders in the ebpf-guard codebase to prevent deadlocks and maintain consistency.

## Overview

Maintaining a strict lock ordering hierarchy is essential to prevent deadlocks. When multiple locks must be held simultaneously, they must always be acquired in the same order.

## Lock Hierarchy

```
ProfileManager.mu (highest)
    ↓
ProcessProfile.mu
    ↓
AnomalyDetector.mu (lowest)
```

## Detailed Lock Orderings

### 1. ProfileManager → ProcessProfile

**Location:** `internal/profiler/profile.go:RecordEvent`

```go
// Lock order: pm.mu must be acquired before profile.mu
// This invariant is also documented in AnomalyDetector.calculateAnomalyScore.
func (pm *ProfileManager) RecordEvent(e types.Event) {
    pm.mu.Lock()
    // ... find or create profile ...
    
    // When accessing profile data, pm.mu is held, then profile.mu is acquired
    profile.mu.RLock()  // or Lock()
    // ... access profile data ...
    profile.mu.RUnlock()
    
    pm.mu.Unlock()
}
```

**Rationale:** The ProfileManager owns the map of profiles. To ensure atomicity of the "find or create" operation, the manager lock must be held while accessing individual profiles.

---

### 2. ProfileManager → ProcessProfile (via AnomalyDetector)

**Location:** `internal/profiler/anomaly.go:calculateAnomalyScore`

```go
// Lock order: pm.mu must be acquired before profile.mu (see ProfileManager.RecordEvent).
func (ad *AnomalyDetector) calculateAnomalyScore(profile *ProcessProfile, event types.Event) *AnomalyResult {
    profile.mu.RLock()
    defer profile.mu.RUnlock()
    // ... calculate score using profile data ...
}
```

**Rationale:** This function is called from `ProcessEvent` after the profile has been retrieved via `ProfileManager`. The lock ordering is established by the caller.

---

### 3. AnomalyDetector Internal Locking

**Location:** `internal/profiler/anomaly.go`

```go
type AnomalyDetector struct {
    mu sync.RWMutex
    // ... other fields ...
    learningComplete atomic.Bool  // Lock-free hot path
}
```

**Pattern:**
- `learningComplete` uses `atomic.Bool` for the hot read path (no mutex needed)
- `mu` protects the learner and other mutable state
- Write to `learningComplete` only happens inside `mu.Lock()`

**Hot Path Optimization:**
```go
func (ad *AnomalyDetector) IsLearningComplete() bool {
    // Fast path: atomic read, no mutex
    if ad.learningComplete.Load() {
        return true
    }
    // Slow path: check learner under lock
    ad.mu.Lock()
    defer ad.mu.Unlock()
    // ... update atomic if complete ...
}
```

---

### 4. AlertmanagerClient Locking

**Location:** `internal/exporter/alertmanager.go`

```go
type AlertmanagerClient struct {
    mu sync.Mutex
    // ... other fields ...
}
```

**Pattern:** Single mutex protects all mutable state (batch, timer, closed flag).

**Special Considerations:**
- Timer callback also acquires `mu` - potential for race with `flushUnlocked`
- `timer = nil` is set before spawning goroutine to prevent double-flush
- `sync.WaitGroup` tracks in-flight `sendBatch` goroutines for graceful shutdown

---

### 5. AnomalyScoreGuard Locking

**Location:** `internal/exporter/cardinality.go`

```go
type AnomalyScoreGuard struct {
    mu      sync.RWMutex
    entries map[string]*AnomalyScoreEntry
    heap    AnomalyScoreHeap
}
```

**Pattern:** Single mutex protects both the map and the heap.

**Important:** The heap is modified under the same lock as the map to maintain consistency between `entries` and `heap`.

---

### 6. CorrelationEngine Locking

**Location:** `internal/correlator/engine.go`

```go
type CorrelationEngine struct {
    // Uses sharded locks for scalability
    shards [16]*eventBufferShard
}

type eventBufferShard struct {
    mu      sync.RWMutex
    buffers map[uint32]*ringBuffer
}
```

**Pattern:** PID-keyed sharding reduces contention. Each shard has its own mutex.

**Lock Scope:**
- Shard selection: `shard := e.PID % 16`
- Only one shard lock is held at a time
- No cross-shard locking (prevents deadlocks)

---

### 7. Server Locking

**Location:** `internal/exporter/server.go`

```go
type Server struct {
    mu sync.RWMutex
    // ... health state ...
}
```

**Pattern:** Simple RWMutex for health/readiness state.

**Note:** HTTP handlers use RLock for reads, Lock for updates. No nested locking.

---

### 8. Config Manager Locking

**Location:** `internal/config/config.go`

```go
type Manager struct {
    mu     sync.RWMutex
    config *Config
}
```

**Pattern:**
- `Get()`: RLock, copy pointer, RUnlock
- `Watch()` callback: Lock, update config, call handlers, Unlock

---

## Anti-Patterns to Avoid

### 1. Lock Upgrade (RWMutex)

**Bad:**
```go
mu.RLock()
if needsWrite {
    mu.RUnlock()
    mu.Lock()  // Race window here!
    // ...
    mu.Unlock()
}
```

**Good:**
```go
mu.Lock()  // Just use full lock if write is possible
// ...
mu.Unlock()
```

### 2. Inconsistent Ordering

**Bad:**
```go
// Goroutine A
pm.mu.Lock()
profile.mu.Lock()  // A: pm -> profile

// Goroutine B
profile.mu.Lock()
pm.mu.Lock()  // B: profile -> pm (DEADLOCK!)
```

### 3. Holding Locks During I/O

**Bad:**
```go
mu.Lock()
result := http.Get(url)  // Blocks with lock held!
mu.Unlock()
```

**Good:**
```go
mu.Lock()
data := copyOfData
mu.Unlock()
result := http.Get(url)  // No lock held
```

## Verification

To verify lock ordering at runtime (Linux only):

```bash
go test -race ./internal/...
```

The race detector will report potential deadlocks and data races.

## Adding New Locks

When adding new mutexes:

1. Determine where in the hierarchy it belongs
2. Document the lock order at all acquisition sites
3. Add a note in this file
4. Run the race detector to verify

## References

- [Go Memory Model](https://golang.org/ref/mem)
- [Go Race Detector](https://golang.org/doc/articles/race_detector)
- Sprint 13.2: Added `atomic.Bool` for hot path optimization
