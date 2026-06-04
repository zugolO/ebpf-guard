package autolearn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func makeSyscallEvent(nr int64) types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	return types.Event{
		Type:    types.EventSyscall,
		PID:     1000,
		Comm:    comm,
		Syscall: &types.SyscallEvent{Nr: nr},
	}
}

func makeNetworkEvent(ip string, port uint16) types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	var daddr [16]byte
	parts := [4]byte{}
	n, _ := parseIPv4(ip, &parts)
	if n == 4 {
		copy(daddr[:4], parts[:])
	}
	return types.Event{
		Type: types.EventTCPConnect,
		PID:  1000,
		Comm: comm,
		Network: &types.NetworkEvent{
			Daddr:  daddr,
			Dport:  port,
			Family: types.AFInet,
		},
	}
}

func makeFileEvent(path string) types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	var fn [256]byte
	copy(fn[:], path)
	return types.Event{
		Type: types.EventFileAccess,
		PID:  1000,
		Comm: comm,
		File: &types.FileEvent{
			Filename: fn,
		},
	}
}

func parseIPv4(ip string, out *[4]byte) (int, error) {
	parts := [4]byte{}
	n := 0
	cur := 0
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			if n >= 4 {
				return 0, nil
			}
			parts[n] = byte(cur)
			n++
			cur = 0
		} else {
			cur = cur*10 + int(ip[i]-'0')
		}
	}
	copy(out[:], parts[:])
	return n, nil
}

func TestSessionBasicIngestion(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	s.Ingest(makeSyscallEvent(0))  // read
	s.Ingest(makeSyscallEvent(1))  // write
	s.Ingest(makeSyscallEvent(59)) // execve
	s.Ingest(makeNetworkEvent("10.0.0.1", 443))
	s.Ingest(makeFileEvent("/etc/nginx/nginx.conf"))

	snap := s.Snapshot()

	if len(snap.Syscalls) != 3 {
		t.Errorf("expected 3 syscalls, got %d", len(snap.Syscalls))
	}
	if len(snap.DestPorts) != 1 {
		t.Errorf("expected 1 dest port, got %d", len(snap.DestPorts))
	}
	if len(snap.DestIPs) != 1 {
		t.Errorf("expected 1 dest IP, got %d", len(snap.DestIPs))
	}
	if len(snap.FileDirs) == 0 {
		t.Error("expected at least 1 file dir")
	}
}

func TestSessionDeduplication(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})

	// Same events ingested multiple times should be deduplicated
	for i := 0; i < 100; i++ {
		s.Ingest(makeSyscallEvent(0)) // read
		s.Ingest(makeNetworkEvent("10.0.0.1", 443))
	}

	snap := s.Snapshot()
	if len(snap.Syscalls) != 1 {
		t.Errorf("expected 1 unique syscall, got %d", len(snap.Syscalls))
	}
	if len(snap.DestPorts) != 1 {
		t.Errorf("expected 1 unique port, got %d", len(snap.DestPorts))
	}
}

func TestSessionNamespaceFilter(t *testing.T) {
	s := NewSession(SessionConfig{
		Duration:  time.Minute,
		Namespace: "production",
	})

	// Event without enrichment — should be filtered out
	s.Ingest(makeSyscallEvent(0))

	// Event with matching namespace
	e := makeSyscallEvent(1)
	e.Enrichment = &types.EnrichmentInfo{Namespace: "production"}
	s.Ingest(e)

	// Event with different namespace
	e2 := makeSyscallEvent(2)
	e2.Enrichment = &types.EnrichmentInfo{Namespace: "staging"}
	s.Ingest(e2)

	snap := s.Snapshot()
	if len(snap.Syscalls) != 1 {
		t.Errorf("expected 1 syscall (filtered), got %d", len(snap.Syscalls))
	}
}

func TestSessionRun(t *testing.T) {
	s := NewSession(SessionConfig{Duration: 50 * time.Millisecond})

	ch := make(chan types.Event, 10)
	ch <- makeSyscallEvent(0)
	ch <- makeSyscallEvent(1)

	ctx := context.Background()
	snap := s.Run(ctx, ch)

	if snap.EventCount != 2 {
		t.Errorf("expected 2 events, got %d", snap.EventCount)
	}
}

func TestExportRules(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute, CommFilter: "nginx"})
	s.Ingest(makeSyscallEvent(0))
	s.Ingest(makeSyscallEvent(1))
	s.Ingest(makeNetworkEvent("10.0.0.1", 443))
	s.Ingest(makeFileEvent("/etc/nginx/nginx.conf"))
	snap := s.Snapshot()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := snap.ExportRules(rulesPath); err != nil {
		t.Fatalf("ExportRules: %v", err)
	}

	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read rules file: %v", err)
	}
	if len(data) == 0 {
		t.Error("rules file is empty")
	}
	content := string(data)
	if len(content) < 100 {
		t.Errorf("rules file suspiciously short (%d bytes)", len(data))
	}
}

func TestExportSeccomp(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})
	s.Ingest(makeSyscallEvent(0))  // read
	s.Ingest(makeSyscallEvent(1))  // write
	s.Ingest(makeSyscallEvent(59)) // execve
	snap := s.Snapshot()

	dir := t.TempDir()
	seccompPath := filepath.Join(dir, "seccomp.json")
	if err := snap.ExportSeccomp(seccompPath); err != nil {
		t.Fatalf("ExportSeccomp: %v", err)
	}

	data, err := os.ReadFile(seccompPath)
	if err != nil {
		t.Fatalf("read seccomp file: %v", err)
	}
	content := string(data)
	// Verify JSON contains expected syscall names
	for _, name := range []string{"read", "write", "execve", "SCMP_ACT_ERRNO", "SCMP_ACT_ALLOW"} {
		if !containsStr(content, name) {
			t.Errorf("seccomp profile missing %q", name)
		}
	}
}

func TestExportAll(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute, CommFilter: "myapp"})
	s.Ingest(makeSyscallEvent(0))
	snap := s.Snapshot()

	dir := t.TempDir()
	rulesPath, seccompPath, err := snap.ExportAll(dir)
	if err != nil {
		t.Fatalf("ExportAll: %v", err)
	}
	for _, p := range []string{rulesPath, seccompPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("output file missing: %s: %v", p, err)
		}
	}
}

func TestSummary(t *testing.T) {
	s := NewSession(SessionConfig{Duration: time.Minute})
	s.Ingest(makeSyscallEvent(0))
	snap := s.Snapshot()
	summary := snap.Summary()
	if !containsStr(summary, "Auto-Profile Summary") {
		t.Error("summary missing header")
	}
	if !containsStr(summary, "read") {
		t.Error("summary missing syscall name")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStrLinear(s, sub))
}

func containsStrLinear(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
