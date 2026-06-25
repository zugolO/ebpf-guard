package collector

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNewSyntheticCollector_Defaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewSyntheticCollector(logger, 0) // 0 → use default interval
	require.NotNil(t, c)
	assert.Equal(t, "synthetic", c.Name())
}

func TestNewSyntheticCollector_CustomInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewSyntheticCollector(logger, 50*time.Millisecond)
	require.NotNil(t, c)
}

func TestSyntheticCollector_IsHealthy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewSyntheticCollector(logger, time.Second)
	assert.True(t, c.IsHealthy())
}

func TestSyntheticCollector_LoadError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewSyntheticCollector(logger, time.Second)
	assert.NoError(t, c.LoadError())
}

// TestSyntheticCollector_SendsEvents verifies that Start sends events on the output
// channel and that we can cancel it via context.
func TestSyntheticCollector_SendsEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewSyntheticCollector(logger, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 100)

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx, out)
	}()

	// Wait for at least one event
	select {
	case e := <-out:
		assert.NotZero(t, e.Type)
		assert.NotZero(t, e.PID)
		assert.NotZero(t, e.Timestamp)
	case <-time.After(500*time.Millisecond):
		t.Fatal("timed out waiting for synthetic event")
	}

	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

// TestSyntheticCollector_EventTypes verifies all generated events have a known type
// and the type-specific payload is non-nil.
func TestSyntheticCollector_EventTypes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewSyntheticCollector(logger, 1*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 256)

	go func() { _ = c.Start(ctx, out) }()

	// Collect events for a short period
	<-ctx.Done()

	collected := len(out)
	require.Greater(t, collected, 0, "must receive at least one event")

	for i := 0; i < collected; i++ {
		e := <-out
		switch e.Type {
		case types.EventSyscall:
			assert.NotNil(t, e.Syscall)
		case types.EventTCPConnect:
			assert.NotNil(t, e.Network)
		case types.EventFileAccess:
			assert.NotNil(t, e.File)
		case types.EventCloudAudit:
			assert.NotNil(t, e.CloudAudit)
		case types.EventIOUring:
			assert.NotNil(t, e.IOUring)
		default:
			t.Errorf("unexpected event type: %d", e.Type)
		}
	}
}

// TestSyntheticCollector_Close verifies that Close returns without hanging after
// Start has returned.
func TestSyntheticCollector_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewSyntheticCollector(logger, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan types.Event, 64)

	startDone := make(chan struct{})
	go func() {
		defer close(startDone)
		_ = c.Start(ctx, out)
	}()

	// Give it a moment to start
	time.Sleep(30 * time.Millisecond)
	cancel()

	// Wait for Start to return
	select {
	case <-startDone:
	case <-time.After(time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}

	// Close must return promptly
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Close()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not return")
	}
}
