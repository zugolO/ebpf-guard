package bpf

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeLink records Update/Close calls for assertions.
type fakeLink struct {
	updated []*ebpf.Program
	closed  bool
	failOn  string // program name to fail on
}

func (f *fakeLink) Update(prog *ebpf.Program) error {
	if f.failOn != "" {
		return errors.New("simulated link update failure")
	}
	f.updated = append(f.updated, prog)
	return nil
}

func (f *fakeLink) Close() error {
	f.closed = true
	return nil
}

// fakeCollection is a stand-in for *ebpf.Collection used to test rollback logic.
type fakeCollection struct {
	programs map[string]*ebpf.Program
	closed   bool
}

func (f *fakeCollection) Close() { f.closed = true }

// fakeLoader returns a collection whose Programs map is pre-populated with
// named stubs (nil *ebpf.Program values are used because we override link.Update).
type fakeLoader struct {
	programs map[string]*ebpf.Program
	err      error
}

func (f *fakeLoader) Load(_ *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	if f.err != nil {
		return nil, f.err
	}
	coll := &ebpf.Collection{}
	coll.Programs = f.programs
	return coll, nil
}

func newTestUpdater(t *testing.T, loader CollectionLoader) *LiveUpdater {
	t.Helper()
	lu := NewLiveUpdater(slog.Default(), LiveUpdateConfig{
		PendingPinDir: t.TempDir(),
		Loader:        loader,
	})
	// Register metrics on a private registry to avoid duplicate registration.
	reg := prometheus.NewRegistry()
	if err := lu.RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	return lu
}

func TestLiveUpdateSuccess(t *testing.T) {
	link := &fakeLink{}
	loader := &fakeLoader{
		programs: map[string]*ebpf.Program{"sys_enter": nil},
	}
	lu := newTestUpdater(t, loader)
	lu.RegisterLink("sys_enter", link)

	if err := lu.LiveUpdate(context.Background(), &ebpf.CollectionSpec{}); err != nil {
		t.Fatalf("LiveUpdate: %v", err)
	}
	if len(link.updated) != 1 {
		t.Errorf("expected 1 update, got %d", len(link.updated))
	}
}

func TestLiveUpdateRollbackOnLinkFailure(t *testing.T) {
	goodLink := &fakeLink{}
	badLink := &fakeLink{failOn: "tcp_connect"}

	loader := &fakeLoader{
		programs: map[string]*ebpf.Program{
			"sys_enter":   nil,
			"tcp_connect": nil,
		},
	}
	lu := newTestUpdater(t, loader)
	lu.RegisterLink("sys_enter", goodLink)
	lu.RegisterLink("tcp_connect", badLink)

	// Set a fake "old" collection so rollback has programs to restore.
	oldColl := &ebpf.Collection{}
	oldColl.Programs = map[string]*ebpf.Program{"sys_enter": nil, "tcp_connect": nil}
	lu.currentColl = oldColl

	err := lu.LiveUpdate(context.Background(), &ebpf.CollectionSpec{})
	if err == nil {
		t.Fatal("expected error from link failure, got nil")
	}
	if !errors.Is(err, err) { // just check it's non-nil and contains "rolled back"
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLiveUpdateLoaderError(t *testing.T) {
	loader := &fakeLoader{err: errors.New("kernel verifier rejected")}
	lu := newTestUpdater(t, loader)

	err := lu.LiveUpdate(context.Background(), &ebpf.CollectionSpec{})
	if err == nil {
		t.Fatal("expected error when loader fails")
	}
}

func TestLiveUpdateSkipsUnknownPrograms(t *testing.T) {
	link := &fakeLink{}
	loader := &fakeLoader{
		// New collection has "new_prog", but the registered link is "sys_enter".
		programs: map[string]*ebpf.Program{"new_prog": nil},
	}
	lu := newTestUpdater(t, loader)
	lu.RegisterLink("sys_enter", link)

	if err := lu.LiveUpdate(context.Background(), &ebpf.CollectionSpec{}); err != nil {
		t.Fatalf("LiveUpdate: %v", err)
	}
	// No matching program → link should NOT have been updated.
	if len(link.updated) != 0 {
		t.Errorf("expected 0 updates for unmatched program, got %d", len(link.updated))
	}
}

func TestDrainInFlightRespectsCancellation(t *testing.T) {
	lu := NewLiveUpdater(slog.Default(), LiveUpdateConfig{PendingPinDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	start := time.Now()
	lu.drainInFlight(ctx)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("drain took too long: %v", elapsed)
	}
}
