package autolearn

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// --- Duration / learning-period completion tests ---

func TestLearningPeriod_RunCompletesAfterDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}
	s := NewSession(SessionConfig{Duration: 60 * time.Millisecond})
	ch := make(chan types.Event, 5)

	start := time.Now()
	snap := s.Run(context.Background(), ch)
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond {
		t.Errorf("Run returned too early (%v), expected at least 50ms", elapsed)
	}
	if snap == nil {
		t.Fatal("expected non-nil Snapshot after session completes")
	}
}

func TestLearningPeriod_RunCancelled_ReturnsSnapshot(t *testing.T) {
	s := NewSession(SessionConfig{Duration: 10 * time.Minute}) // long window
	ch := make(chan types.Event, 5)
	ch <- makeSyscallEvent(0)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan *Snapshot, 1)
	go func() { done <- s.Run(ctx, ch) }()

	cancel() // cancel immediately

	select {
	case snap := <-done:
		if snap == nil {
			t.Error("expected non-nil Snapshot on cancellation")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestLearningPeriod_RunClosedChannel_ReturnsSnapshot(t *testing.T) {
	s := NewSession(SessionConfig{Duration: 10 * time.Minute})
	ch := make(chan types.Event, 3)
	ch <- makeSyscallEvent(1)
	ch <- makeSyscallEvent(2)
	close(ch)

	snap := s.Run(context.Background(), ch)

	if snap == nil {
		t.Fatal("expected Snapshot after channel close")
	}
	if snap.EventCount != 2 {
		t.Errorf("expected 2 events, got %d", snap.EventCount)
	}
}

func TestLearningPeriod_SnapshotContainsDuration(t *testing.T) {
	dur := 150 * time.Millisecond
	s := NewSession(SessionConfig{Duration: dur})
	ch := make(chan types.Event)
	close(ch)

	snap := s.Run(context.Background(), ch)
	if snap.Duration != dur {
		t.Errorf("snapshot Duration: want %v, got %v", dur, snap.Duration)
	}
}

func TestLearningPeriod_SnapshotContainsGeneratedAt(t *testing.T) {
	before := time.Now()
	s := NewSession(SessionConfig{Duration: time.Millisecond})
	ch := make(chan types.Event)
	close(ch)

	snap := s.Run(context.Background(), ch)
	after := time.Now()

	if snap.GeneratedAt.Before(before) || snap.GeneratedAt.After(after) {
		t.Errorf("GeneratedAt %v out of range [%v, %v]", snap.GeneratedAt, before, after)
	}
}

func TestLearningPeriod_EventCountAccumulates(t *testing.T) {
	s := NewSession(SessionConfig{Duration: 10 * time.Minute})
	ch := make(chan types.Event, 10)

	const n = 7
	for i := 0; i < n; i++ {
		ch <- makeSyscallEvent(int64(i))
	}
	close(ch)

	snap := s.Run(context.Background(), ch)
	if snap.EventCount != n {
		t.Errorf("expected EventCount=%d, got %d", n, snap.EventCount)
	}
}

// --- Filter tests ---

func TestLearningPeriod_ContainerIDFilter_AcceptsMatch(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:    time.Minute,
		ContainerID: "abc123",
	})

	e := makeSyscallEvent(1)
	e.Enrichment = &types.EnrichmentInfo{ContainerID: "abc123"}
	s.Ingest(e)

	snap := s.Snapshot()
	if snap.EventCount != 1 {
		t.Errorf("expected 1 event matching container filter, got %d", snap.EventCount)
	}
}

func TestLearningPeriod_ContainerIDFilter_RejectsOther(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:    time.Minute,
		ContainerID: "abc123",
	})

	e := makeSyscallEvent(1)
	e.Enrichment = &types.EnrichmentInfo{ContainerID: "xyz999"}
	s.Ingest(e)

	snap := s.Snapshot()
	if snap.EventCount != 0 {
		t.Errorf("expected 0 events for different container, got %d", snap.EventCount)
	}
}

func TestLearningPeriod_ContainerIDFilter_RejectsNoEnrichment(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:    time.Minute,
		ContainerID: "abc123",
	})
	s.Ingest(makeSyscallEvent(1)) // no enrichment

	snap := s.Snapshot()
	if snap.EventCount != 0 {
		t.Errorf("expected 0 events without enrichment, got %d", snap.EventCount)
	}
}

func TestLearningPeriod_CommFilter_AcceptsPrefix(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:   time.Minute,
		CommFilter: "nginx",
	})

	s.Ingest(makeSyscallEvent(0)) // comm is "nginx" from helper
	snap := s.Snapshot()
	if snap.EventCount != 1 {
		t.Errorf("expected 1 event matching comm prefix, got %d", snap.EventCount)
	}
}

func TestLearningPeriod_CommFilter_RejectsMismatch(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:   time.Minute,
		CommFilter: "postgres",
	})

	s.Ingest(makeSyscallEvent(0)) // comm is "nginx"
	snap := s.Snapshot()
	if snap.EventCount != 0 {
		t.Errorf("expected 0 events for comm mismatch, got %d", snap.EventCount)
	}
}

func TestLearningPeriod_NoFilter_AcceptsAll(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	s.Ingest(makeSyscallEvent(0))

	e := makeSyscallEvent(1)
	e.Enrichment = &types.EnrichmentInfo{Namespace: "prod", ContainerID: "c1"}
	s.Ingest(e)

	snap := s.Snapshot()
	if snap.EventCount != 2 {
		t.Errorf("expected 2 events with no filter, got %d", snap.EventCount)
	}
}

// --- Exec-path tracking ---

func TestLearningPeriod_ExecPaths_RecordedForBinaries(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	s.Ingest(makeFileEvent("/usr/bin/curl"))
	s.Ingest(makeFileEvent("/etc/nginx/nginx.conf")) // not an exec path

	snap := s.Snapshot()
	if len(snap.ExecPaths) != 1 {
		t.Errorf("expected 1 exec path (/usr/bin/curl), got %d: %v", len(snap.ExecPaths), snap.ExecPaths)
	}
}

func TestLearningPeriod_ExecPaths_MultipleTracked(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	for _, p := range []string{"/bin/sh", "/usr/bin/python3", "/usr/sbin/sshd"} {
		s.Ingest(makeFileEvent(p))
	}

	snap := s.Snapshot()
	if len(snap.ExecPaths) != 3 {
		t.Errorf("expected 3 exec paths, got %d: %v", len(snap.ExecPaths), snap.ExecPaths)
	}
}

// --- Snapshot fields ---

func TestLearningPeriod_SnapshotContainsFilters(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:    time.Minute,
		Namespace:   "prod",
		ContainerID: "c42",
		CommFilter:  "nginx",
	})

	ch := make(chan types.Event)
	close(ch)
	snap := s.Run(context.Background(), ch)

	if snap.Namespace != "prod" {
		t.Errorf("snapshot Namespace: got %q", snap.Namespace)
	}
	if snap.ContainerID != "c42" {
		t.Errorf("snapshot ContainerID: got %q", snap.ContainerID)
	}
	if snap.CommFilter != "nginx" {
		t.Errorf("snapshot CommFilter: got %q", snap.CommFilter)
	}
}

func TestLearningPeriod_EmptySession_AllSlicesNonNil(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})
	snap := s.Snapshot()

	if snap.Syscalls == nil {
		t.Error("Syscalls should be non-nil slice")
	}
	if snap.DestPorts == nil {
		t.Error("DestPorts should be non-nil slice")
	}
	if snap.DestIPs == nil {
		t.Error("DestIPs should be non-nil slice")
	}
	if snap.FileDirs == nil {
		t.Error("FileDirs should be non-nil slice")
	}
	if snap.ExecPaths == nil {
		t.Error("ExecPaths should be non-nil slice")
	}
	if snap.Comms == nil {
		t.Error("Comms should be non-nil slice")
	}
}

// --- isExecutablePath helper ---

func TestIsExecutablePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/bin/sh", true},
		{"/sbin/init", true},
		{"/usr/bin/curl", true},
		{"/usr/sbin/sshd", true},
		{"/usr/local/bin/myapp", true},
		{"/etc/nginx/nginx.conf", false},
		{"/tmp/evil", false},
		{"/var/log/app.log", false},
		{"/home/user/script.sh", false},
	}
	for _, tt := range tests {
		got := isExecutablePath(tt.path)
		if got != tt.want {
			t.Errorf("isExecutablePath(%q): got %v, want %v", tt.path, got, tt.want)
		}
	}
}

// --- extractDir helper ---

func TestExtractDir(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/etc/nginx/nginx.conf", "/etc/nginx/"},
		{"/usr/bin/curl", "/usr/bin/"},
		{"/file-at-root", "/"},
		{"", ""},
		{"no-slash", ""},
	}
	for _, tt := range tests {
		got := extractDir(tt.path)
		if got != tt.want {
			t.Errorf("extractDir(%q): got %q, want %q", tt.path, got, tt.want)
		}
	}
}
