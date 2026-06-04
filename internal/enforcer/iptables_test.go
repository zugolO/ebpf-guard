package enforcer

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

// newDryRunIPT returns a dry-run IPTablesManager for unit tests.
func newDryRunIPT(t *testing.T) *IPTablesManager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mgr, err := NewIPTablesManager(logger, IPTablesConfig{DryRun: true})
	if err != nil {
		t.Fatalf("NewIPTablesManager: %v", err)
	}
	return mgr
}

func TestNewIPTablesManager_DryRun(t *testing.T) {
	mgr := newDryRunIPT(t)
	if mgr.GetBackendName() != "iptables" {
		t.Errorf("GetBackendName = %q, want \"iptables\"", mgr.GetBackendName())
	}
	if err := mgr.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestIPTablesManager_BlockUID_DryRun(t *testing.T) {
	mgr := newDryRunIPT(t)
	ctx := context.Background()

	if err := mgr.BlockUID(ctx, 1001); err != nil {
		t.Fatalf("BlockUID: %v", err)
	}

	uids := mgr.GetBlockedUIDs()
	if len(uids) != 1 || uids[0] != 1001 {
		t.Errorf("GetBlockedUIDs = %v, want [1001]", uids)
	}

	// Idempotent block.
	if err := mgr.BlockUID(ctx, 1001); err != nil {
		t.Errorf("BlockUID idempotent: %v", err)
	}
	if n := len(mgr.GetBlockedUIDs()); n != 1 {
		t.Errorf("expected 1 blocked UID after duplicate block, got %d", n)
	}
}

func TestIPTablesManager_UnblockUID_DryRun(t *testing.T) {
	mgr := newDryRunIPT(t)
	ctx := context.Background()

	if err := mgr.BlockUID(ctx, 2000); err != nil {
		t.Fatalf("BlockUID: %v", err)
	}
	if err := mgr.UnblockUID(ctx, 2000); err != nil {
		t.Fatalf("UnblockUID: %v", err)
	}

	for _, uid := range mgr.GetBlockedUIDs() {
		if uid == 2000 {
			t.Error("UID 2000 should not be in blocked list after unblock")
		}
	}

	// Unblocking non-existent is a no-op.
	if err := mgr.UnblockUID(ctx, 9999); err != nil {
		t.Errorf("UnblockUID non-existent: %v", err)
	}
}

func TestIPTablesManager_BlockIP_DryRun(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"IPv4", "203.0.113.1", false},
		{"IPv6", "2001:db8::1", false},
		{"Invalid", "not-an-ip", true},
		{"Empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newDryRunIPT(t)
			err := mgr.BlockIP(context.Background(), tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("BlockIP(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestIPTablesManager_UnblockIP_DryRun(t *testing.T) {
	mgr := newDryRunIPT(t)
	ctx := context.Background()

	if err := mgr.BlockIP(ctx, "198.51.100.1"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if err := mgr.UnblockIP(ctx, "198.51.100.1"); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}

	for _, ip := range mgr.GetBlockedIPs() {
		if ip == "198.51.100.1" {
			t.Error("IP should be removed after UnblockIP")
		}
	}

	// Unblocking invalid IP returns an error.
	if err := mgr.UnblockIP(ctx, "bad-ip"); err == nil {
		t.Error("UnblockIP(bad-ip) should return an error")
	}

	// Unblocking non-blocked IP is a no-op.
	if err := mgr.UnblockIP(ctx, "192.0.2.99"); err != nil {
		t.Errorf("UnblockIP non-blocked: %v", err)
	}
}

func TestIPTablesManager_Cleanup_DryRun(t *testing.T) {
	mgr := newDryRunIPT(t)
	ctx := context.Background()

	_ = mgr.BlockUID(ctx, 100)
	_ = mgr.BlockUID(ctx, 200)
	_ = mgr.BlockIP(ctx, "10.0.0.1")

	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if n := len(mgr.GetBlockedUIDs()); n != 0 {
		t.Errorf("expected 0 blocked UIDs after cleanup, got %d", n)
	}
	if n := len(mgr.GetBlockedIPs()); n != 0 {
		t.Errorf("expected 0 blocked IPs after cleanup, got %d", n)
	}
}

func TestIPTablesManager_IsAvailable_DryRun(t *testing.T) {
	// In dry-run mode no binaries are discovered, IsAvailable returns false.
	mgr := newDryRunIPT(t)
	// We don't assert a value — just that it doesn't panic.
	_ = mgr.IsAvailable()
}

func TestIsIPTablesAvailable(t *testing.T) {
	// Just verify the function runs; result depends on the host environment.
	_ = IsIPTablesAvailable()
}

// TestEnforcer_IPTablesBackend verifies that the enforcer initialises the
// iptables manager when BlockBackend == "iptables" with DryRun=true.
func TestEnforcer_IPTablesBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	e, err := NewEnforcer(logger, Config{
		EnableBlock:  true,
		BlockBackend: BlockBackendIPTables,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	defer e.Close()

	if e.iptablesMgr == nil {
		t.Error("iptablesMgr should be non-nil when BlockBackend=iptables")
	}
	if e.iptablesMgr.GetBackendName() != "iptables" {
		t.Errorf("backend name = %q, want \"iptables\"", e.iptablesMgr.GetBackendName())
	}
}
