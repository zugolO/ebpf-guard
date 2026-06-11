package autolearn

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// --- Race-condition / concurrency tests ---
// All of these are designed to be run with -race to surface data races.

func TestConcurrent_IngestFromManyGoroutines(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		nr := int64(i % 20) // keep syscall space small to stress deduplication
		go func() {
			defer wg.Done()
			s.Ingest(makeSyscallEvent(nr))
		}()
	}
	wg.Wait()

	snap := s.Snapshot()
	if snap.EventCount == 0 {
		t.Error("expected non-zero event count after concurrent ingest")
	}
	if len(snap.Syscalls) > 20 {
		t.Errorf("expected at most 20 unique syscalls, got %d", len(snap.Syscalls))
	}
}

func TestConcurrent_IngestAndSnapshot(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	const producers = 20
	const snapshotters = 10

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Producers continuously ingest events.
	wg.Add(producers)
	for i := 0; i < producers; i++ {
		go func(n int64) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.Ingest(makeSyscallEvent(n % 10))
				}
			}
		}(int64(i))
	}

	// Snapshotters concurrently read the snapshot.
	wg.Add(snapshotters)
	for i := 0; i < snapshotters; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.Snapshot()
				}
			}
		}()
	}

	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestConcurrent_IngestMixedEventTypes(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			switch i % 3 {
			case 0:
				s.Ingest(makeSyscallEvent(int64(i)))
			case 1:
				s.Ingest(makeNetworkEvent("10.0.0.1", uint16(8000+i)))
			case 2:
				s.Ingest(makeFileEvent("/etc/config.yaml"))
			}
		}()
	}
	wg.Wait()

	snap := s.Snapshot()
	if snap.EventCount == 0 {
		t.Error("expected events after concurrent mixed-type ingest")
	}
}

func TestConcurrent_RunAndExternalIngest(t *testing.T) {
	// Verify that calling Ingest concurrently with Run does not race.
	s := NewSession(SessionConfig{Duration: 60 * time.Millisecond})
	ch := make(chan types.Event, 100)

	var wg sync.WaitGroup
	wg.Add(1)

	var snap *Snapshot
	go func() {
		defer wg.Done()
		snap = s.Run(context.Background(), ch)
	}()

	// Pump events both through the channel and directly via Ingest concurrently.
	for i := 0; i < 50; i++ {
		ch <- makeSyscallEvent(int64(i % 10))
		s.Ingest(makeNetworkEvent("10.0.0.1", uint16(443)))
	}

	wg.Wait()

	if snap == nil {
		t.Fatal("expected non-nil Snapshot from Run")
	}
}

func TestConcurrent_ConcurrentSnapshotsAreIndependent(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})
	s.Ingest(makeSyscallEvent(1))
	s.Ingest(makeSyscallEvent(2))

	const snapshots = 20
	snaps := make([]*Snapshot, snapshots)
	var wg sync.WaitGroup
	wg.Add(snapshots)

	for i := 0; i < snapshots; i++ {
		i := i
		go func() {
			defer wg.Done()
			snaps[i] = s.Snapshot()
		}()
	}
	wg.Wait()

	for i, snap := range snaps {
		if snap == nil {
			t.Errorf("snapshot %d is nil", i)
			continue
		}
		if len(snap.Syscalls) != 2 {
			t.Errorf("snapshot %d: expected 2 syscalls, got %d", i, len(snap.Syscalls))
		}
	}
}

func TestConcurrent_NoDeadlockUnderContention(t *testing.T) {
	// Verifies that the session never deadlocks when many goroutines compete.
	s := NewSession(SessionConfig{Duration: time.Minute})

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	for i := 0; i < goroutines; i++ {
		go func(n int64) {
			defer wg.Done()
			s.Ingest(makeSyscallEvent(n % 5))
			_ = s.Snapshot()
		}(int64(i))
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: goroutines did not complete within 5s")
	}
}

func TestConcurrent_EventCountIsConsistent(t *testing.T) {
	// Event count must increase monotonically; a snapshot mid-ingest is acceptable
	// as long as it never exceeds total events sent.
	s := NewSession(SessionConfig{Duration: time.Minute})

	const events = 200
	var ingested atomic.Int64

	var wg sync.WaitGroup
	wg.Add(events)
	for i := 0; i < events; i++ {
		go func(n int64) {
			defer wg.Done()
			s.Ingest(makeSyscallEvent(n % 50))
			ingested.Add(1)
		}(int64(i))
	}
	wg.Wait()

	snap := s.Snapshot()
	if snap.EventCount > uint64(ingested.Load()) {
		t.Errorf("EventCount %d exceeds total ingested %d — impossible", snap.EventCount, ingested.Load())
	}
}

func TestConcurrent_FilteredIngestion_Races(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:   time.Minute,
		CommFilter: "nginx",
		Namespace:  "prod",
	})

	var wg sync.WaitGroup
	const goroutines = 40
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			e := makeSyscallEvent(int64(i % 8))
			if i%2 == 0 {
				// matching namespace
				e.Enrichment = &types.EnrichmentInfo{Namespace: "prod"}
			}
			// Odd goroutines have no enrichment — should be filtered.
			s.Ingest(e)
		}()
	}
	wg.Wait()

	snap := s.Snapshot()
	// Only events with namespace "prod" should be counted.
	if snap.EventCount > uint64(goroutines) {
		t.Errorf("EventCount %d exceeds total goroutines %d", snap.EventCount, goroutines)
	}
}

func TestConcurrent_RunWithHighThroughputChannel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping high-throughput test in short mode")
	}

	s := NewSession(SessionConfig{Duration: 50 * time.Millisecond})
	ch := make(chan types.Event, 1000)

	var sent atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			e := makeSyscallEvent(sent.Load() % 100)
			select {
			case ch <- e:
				sent.Add(1)
			default:
				return
			}
		}
	}()

	snap := s.Run(context.Background(), ch)
	wg.Wait()

	if snap == nil {
		t.Fatal("expected non-nil Snapshot")
	}
	// EventCount must not exceed what was actually sent.
	if snap.EventCount > uint64(sent.Load())+1000 {
		t.Errorf("EventCount %d far exceeds sent %d", snap.EventCount, sent.Load())
	}
}
