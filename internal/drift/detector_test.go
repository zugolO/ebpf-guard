package drift

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func makeEvent(etype types.EventType, cid, namespace, pod string) types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	e := types.Event{
		Type: etype,
		PID:  1000,
		Comm: comm,
		Enrichment: &types.EnrichmentInfo{
			ContainerID: cid,
			Namespace:   namespace,
			PodName:     pod,
		},
	}
	return e
}

func makeSyscallEvent(nr int64, cid string) types.Event {
	e := makeEvent(types.EventSyscall, cid, "default", "mypod")
	e.Syscall = &types.SyscallEvent{Nr: nr}
	return e
}

func makeNetEvent(cid, ip string, port uint16) types.Event {
	e := makeEvent(types.EventTCPConnect, cid, "default", "mypod")
	e.Network = &types.NetworkEvent{
		Dport:  port,
		Family: types.AFInet,
	}
	// We leave Daddr as zeros; FormatIP16 will return "0.0.0.0" and we test just port matching.
	_ = ip
	return e
}

func makeFileEvent(cid, path string) types.Event {
	e := makeEvent(types.EventFileAccess, cid, "default", "mypod")
	var fn [256]byte
	copy(fn[:], path)
	e.File = &types.FileEvent{Filename: fn}
	return e
}

func TestDetectorBaselineWindow(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 50 * time.Millisecond})

	// Events during baseline window should produce no alerts.
	e := makeSyscallEvent(0, "c1")
	alerts := d.Ingest(e)
	if len(alerts) != 0 {
		t.Errorf("expected no alerts during learning, got %d", len(alerts))
	}

	// Wait for baseline to lock.
	time.Sleep(60 * time.Millisecond)

	// Same syscall — no drift.
	alerts = d.Ingest(makeSyscallEvent(0, "c1"))
	if len(alerts) != 0 {
		t.Errorf("expected no alerts for known syscall, got %d", len(alerts))
	}

	// New syscall — drift.
	alerts = d.Ingest(makeSyscallEvent(999, "c1"))
	if len(alerts) != 1 {
		t.Errorf("expected 1 drift alert, got %d", len(alerts))
	}
	if alerts[0].DriftType != DriftNewSyscall {
		t.Errorf("expected DriftNewSyscall, got %s", alerts[0].DriftType)
	}
}

func TestDetectorNoEnrichment(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: time.Second})

	// Event without enrichment should be ignored.
	var comm [16]byte
	e := types.Event{Type: types.EventSyscall, Comm: comm, Syscall: &types.SyscallEvent{Nr: 0}}
	alerts := d.Ingest(e)
	if len(alerts) != 0 {
		t.Errorf("expected no alerts for event without enrichment, got %d", len(alerts))
	}
	if d.BaselineCount() != 0 {
		t.Error("expected no baselines for events without container ID")
	}
}

func TestDetectorNewExecDrift(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 10 * time.Millisecond})

	// Baseline: /usr/bin/nginx is the only known exec.
	d.Ingest(makeFileEvent("c2", "/usr/bin/nginx"))
	time.Sleep(20 * time.Millisecond)

	// Drift: /usr/bin/sh is a new exec not seen in baseline.
	alerts := d.Ingest(makeFileEvent("c2", "/usr/bin/sh"))
	found := false
	for _, a := range alerts {
		if a.DriftType == DriftNewExec {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DriftNewExec alert, got %v", alerts)
	}
}

func TestDetectorNewLibraryDrift(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 10 * time.Millisecond})

	d.Ingest(makeFileEvent("c3", "/usr/lib/libc.so.6"))
	time.Sleep(20 * time.Millisecond)

	// New library should trigger drift.
	alerts := d.Ingest(makeFileEvent("c3", "/usr/lib/librogue.so"))
	found := false
	for _, a := range alerts {
		if a.DriftType == DriftNewLibrary {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DriftNewLibrary alert, got %v", alerts)
	}
}

func TestDetectorNewNetworkDrift(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 10 * time.Millisecond})

	d.Ingest(makeNetEvent("c4", "10.0.0.1", 443))
	time.Sleep(20 * time.Millisecond)

	// Same peer — no drift.
	alerts := d.Ingest(makeNetEvent("c4", "10.0.0.1", 443))
	for _, a := range alerts {
		if a.DriftType == DriftNewNetwork {
			t.Errorf("unexpected DriftNewNetwork for known peer")
		}
	}

	// Different port — drift.
	alerts = d.Ingest(makeNetEvent("c4", "0.0.0.0", 4444))
	found := false
	for _, a := range alerts {
		if a.DriftType == DriftNewNetwork {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DriftNewNetwork alert for new port, got %v", alerts)
	}
}

func TestDetectorIsolation(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 10 * time.Millisecond})

	// Two containers — baselines must be independent.
	d.Ingest(makeSyscallEvent(0, "c5"))
	d.Ingest(makeSyscallEvent(1, "c6"))
	time.Sleep(20 * time.Millisecond)

	// Syscall 1 is unknown to c5, known to c6.
	alertsC5 := d.Ingest(makeSyscallEvent(1, "c5"))
	alertsC6 := d.Ingest(makeSyscallEvent(1, "c6"))

	if len(alertsC5) == 0 {
		t.Error("expected drift alert for c5 (syscall 1 unknown)")
	}
	for _, a := range alertsC6 {
		if a.DriftType == DriftNewSyscall {
			t.Errorf("unexpected drift alert for c6 (syscall 1 should be known)")
		}
	}
}

func TestDriftAlertToTypes(t *testing.T) {
	da := DriftAlert{
		ContainerID: "abc123",
		Namespace:   "production",
		PodName:     "web-pod",
		DriftType:   DriftNewExec,
		Detail:      "new binary /usr/bin/curl",
		Severity:    types.SeverityCritical,
		Timestamp:   time.Now(),
		PID:         42,
		Comm:        "nginx",
	}

	alert := DriftAlertToTypes(da, 1)
	if alert.RuleID == "" {
		t.Error("expected non-empty RuleID")
	}
	if alert.Severity != types.SeverityCritical {
		t.Errorf("expected critical severity, got %s", alert.Severity)
	}
	if alert.Enrichment.ContainerID != "abc123" {
		t.Errorf("expected container ID in enrichment")
	}
}

func TestPurgeStale(t *testing.T) {
	d := NewDetector(DetectorConfig{BaselineWindow: 10 * time.Millisecond})

	d.Ingest(makeSyscallEvent(0, "stale1"))
	d.Ingest(makeSyscallEvent(0, "stale2"))

	time.Sleep(20 * time.Millisecond)

	if d.BaselineCount() != 2 {
		t.Errorf("expected 2 baselines, got %d", d.BaselineCount())
	}

	removed := d.PurgeStale(0) // zero TTL purges everything locked
	if removed != 2 {
		t.Errorf("expected 2 purged, got %d", removed)
	}
	if d.BaselineCount() != 0 {
		t.Errorf("expected 0 baselines after purge, got %d", d.BaselineCount())
	}
}
