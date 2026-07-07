package drift

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// NewDetector defaults
// ─────────────────────────────────────────────────────────────────────────────

func TestNewDetector_DefaultsWindowWhenZero(t *testing.T) {
	d := NewDetector(DetectorConfig{})
	assert.Equal(t, 5*time.Minute, d.window)
}

// ─────────────────────────────────────────────────────────────────────────────
// getOrCreate — concurrent creation race (double-checked locking)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetOrCreate_ConcurrentSameContainer(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: time.Second, Logger: discardLogger()})

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]*ContainerBaseline, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = d.getOrCreate("racy", "ns", "pod")
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 1; i < n; i++ {
		assert.Same(t, results[0], results[i], "all goroutines must observe the same baseline instance")
	}
	assert.Equal(t, 1, d.BaselineCount())
}

// ─────────────────────────────────────────────────────────────────────────────
// snapshotImageForContainer
// ─────────────────────────────────────────────────────────────────────────────

func TestSnapshotImageForContainer_DisabledMode(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: time.Second, Logger: discardLogger()})
	bl := d.getOrCreate("c1", "ns", "pod")

	d.snapshotImageForContainer(bl, makeSyscallEvent(0, "c1"))
	assert.False(t, bl.ImageSnapshotted)
}

func TestSnapshotImageForContainer_AlreadySnapshotted(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: time.Second, ImageManifest: true, Logger: discardLogger()})
	bl := d.getOrCreate("c1", "ns", "pod")
	bl.ImageSnapshotted = true

	d.snapshotImageForContainer(bl, makeSyscallEvent(0, "c1"))
	assert.Equal(t, 0, bl.ImageExecPaths, "already-snapshotted baseline must not be touched again")
}

func TestSnapshotImageForContainer_SnapshotFails(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: time.Second, ImageManifest: true, Logger: discardLogger()})
	bl := d.getOrCreate("c1", "ns", "pod")

	e := makeSyscallEvent(0, "c1")
	e.PID = 999999937 // no such process → SnapshotFromPID returns a manifest.Error.
	d.snapshotImageForContainer(bl, e)

	assert.False(t, bl.ImageSnapshotted, "a failed snapshot must not mark the baseline as snapshotted")
}

// ─────────────────────────────────────────────────────────────────────────────
// record — edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestRecord_EmptyFilePathIgnored(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: time.Hour, Logger: discardLogger()})
	// Still in the learning window: record() runs, must not panic on an empty path.
	alerts := d.Ingest(makeFileEvent("c1", ""))
	require.Empty(t, alerts)
}

func TestRecord_PathWithoutSlash(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: time.Hour, Logger: discardLogger()})
	// A bare filename (no directory component) exercises extractDir's
	// "no slash found" branch without panicking or recording a directory.
	alerts := d.Ingest(makeFileEvent("c1", "bare-filename"))
	require.Empty(t, alerts)
}

// ─────────────────────────────────────────────────────────────────────────────
// checkDrift — edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckDrift_EmptyFilePathIgnored(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 10 * time.Millisecond, Logger: discardLogger()})
	d.Ingest(makeFileEvent("c1", "/usr/bin/nginx"))
	time.Sleep(20 * time.Millisecond)

	alerts := d.Ingest(makeFileEvent("c1", ""))
	assert.Empty(t, alerts)
}

func TestCheckDrift_AllowlistedExecSkipped(t *testing.T) {
	d := NewDetector(DetectorConfig{
		BaselineWindow: 10 * time.Millisecond,
		Logger:         discardLogger(),
		AllowlistExec:  map[string]struct{}{"/usr/local/bin/jit-tool": {}},
	})
	d.Ingest(makeFileEvent("c1", "/usr/bin/nginx"))
	time.Sleep(20 * time.Millisecond)

	// Not in the baseline, but explicitly allowlisted — must not alert.
	alerts := d.Ingest(makeFileEvent("c1", "/usr/local/bin/jit-tool"))
	for _, a := range alerts {
		assert.NotEqual(t, DriftNewExec, a.DriftType, "allowlisted exec must not trigger drift")
	}
}

func TestCheckDrift_NewFileDirectory(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 10 * time.Millisecond, Logger: discardLogger()})
	d.Ingest(makeFileEvent("c1", "/data/known/file.txt"))
	time.Sleep(20 * time.Millisecond)

	alerts := d.Ingest(makeFileEvent("c1", "/data/unknown/other.txt"))
	found := false
	for _, a := range alerts {
		if a.DriftType == DriftNewFileDir {
			found = true
		}
	}
	assert.True(t, found, "expected DriftNewFileDir alert for a new directory, got %v", alerts)
}
