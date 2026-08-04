package profiler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// captureSlog swaps the default slog logger for one writing JSON into a buffer,
// restoring the original when the test ends.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// countCompletionLines returns how many "learning complete" records the buffer holds.
func countCompletionLines(buf *bytes.Buffer) int {
	n := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if msg, _ := rec["msg"].(string); msg == "profiler: learning complete" {
			n++
		}
	}
	return n
}

// P2-15: the operator must see the transition into the working phase in the log.
func TestLearningCompleteIsLogged(t *testing.T) {
	buf := captureSlog(t)

	// LearningPeriod 0 => completion gated purely on reaching minSamples.
	bl := NewBaselineLearner(0, 2)

	if bl.IsLearningComplete() {
		t.Fatal("learning must not be complete before minSamples is reached")
	}
	if got := countCompletionLines(buf); got != 0 {
		t.Fatalf("no completion log expected yet, got %d", got)
	}

	bl.RecordSample()
	bl.RecordSample()

	if !bl.IsLearningComplete() {
		t.Fatal("learning must be complete once minSamples is reached")
	}

	if got := countCompletionLines(buf); got != 1 {
		t.Fatalf("expected exactly 1 completion log line, got %d (log: %s)", got, buf.String())
	}
}

// The completion line must be emitted once, not on every subsequent check.
func TestLearningCompleteLoggedOnlyOnce(t *testing.T) {
	buf := captureSlog(t)

	bl := NewBaselineLearner(0, 1)
	bl.RecordSample()

	for i := 0; i < 20; i++ {
		if !bl.IsLearningComplete() {
			t.Fatal("learning must stay complete")
		}
	}

	if got := countCompletionLines(buf); got != 1 {
		t.Fatalf("completion must be logged exactly once, got %d", got)
	}
}

// Concurrent readers must not produce duplicate completion lines.
func TestLearningCompleteLogRaceFree(t *testing.T) {
	buf := captureSlog(t)

	bl := NewBaselineLearner(0, 1)
	bl.RecordSample()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bl.IsLearningComplete()
		}()
	}
	wg.Wait()

	if got := countCompletionLines(buf); got != 1 {
		t.Fatalf("expected exactly 1 completion log under concurrency, got %d", got)
	}
}
