package enforcer

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestNewNFTablesManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Test dry-run mode (always works)
	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager (dry-run) failed: %v", err)
	}
	defer mgr.Close()

	if !mgr.dryRun {
		t.Error("expected dry-run mode to be enabled")
	}

	if mgr.GetBackendName() != "nftables" {
		t.Errorf("expected backend name 'nftables', got %s", mgr.GetBackendName())
	}
}

func TestNFTablesManager_DryRun(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// All operations should succeed in dry-run mode without actual nftables
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "BlockUID",
			fn:   func() error { return mgr.BlockUID(ctx, 1000) },
		},
		{
			name: "UnblockUID",
			fn:   func() error { return mgr.UnblockUID(ctx, 1000) },
		},
		{
			name: "BlockCgroup",
			fn:   func() error { return mgr.BlockCgroup(ctx, 12345) },
		},
		{
			name: "UnblockCgroup",
			fn:   func() error { return mgr.UnblockCgroup(ctx, 12345) },
		},
		{
			name: "BlockIP",
			fn:   func() error { return mgr.BlockIP(ctx, "192.0.2.1") },
		},
		{
			name: "UnblockIP",
			fn:   func() error { return mgr.UnblockIP(ctx, "192.0.2.1") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err != nil {
				t.Errorf("%s failed: %v", tt.name, err)
			}
		})
	}
}

func TestNFTablesManager_BlockUID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// Block a UID
	if err := mgr.BlockUID(ctx, 1000); err != nil {
		t.Errorf("BlockUID failed: %v", err)
	}

	// Check that it's in the blocked list
	uids := mgr.GetBlockedUIDs()
	found := false
	for _, uid := range uids {
		if uid == 1000 {
			found = true
			break
		}
	}
	if !found {
		t.Error("UID 1000 should be in blocked list")
	}

	// Blocking same UID again should not fail
	if err := mgr.BlockUID(ctx, 1000); err != nil {
		t.Errorf("BlockUID (duplicate) failed: %v", err)
	}
}

func TestNFTablesManager_UnblockUID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// Block then unblock
	if err := mgr.BlockUID(ctx, 1000); err != nil {
		t.Fatalf("BlockUID failed: %v", err)
	}

	if err := mgr.UnblockUID(ctx, 1000); err != nil {
		t.Errorf("UnblockUID failed: %v", err)
	}

	// Check that it's no longer in the blocked list
	uids := mgr.GetBlockedUIDs()
	for _, uid := range uids {
		if uid == 1000 {
			t.Error("UID 1000 should not be in blocked list after unblock")
		}
	}

	// Unblocking non-blocked UID should not fail
	if err := mgr.UnblockUID(ctx, 9999); err != nil {
		t.Errorf("UnblockUID (non-existent) failed: %v", err)
	}
}

func TestNFTablesManager_BlockCgroup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// Block a cgroup
	if err := mgr.BlockCgroup(ctx, 12345); err != nil {
		t.Errorf("BlockCgroup failed: %v", err)
	}

	// Check that it's in the blocked list
	cgroups := mgr.GetBlockedCgroups()
	found := false
	for _, cg := range cgroups {
		if cg == 12345 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Cgroup 12345 should be in blocked list")
	}
}

func TestNFTablesManager_UnblockCgroup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// Block then unblock
	if err := mgr.BlockCgroup(ctx, 12345); err != nil {
		t.Fatalf("BlockCgroup failed: %v", err)
	}

	if err := mgr.UnblockCgroup(ctx, 12345); err != nil {
		t.Errorf("UnblockCgroup failed: %v", err)
	}

	// Check that it's no longer in the blocked list
	cgroups := mgr.GetBlockedCgroups()
	for _, cg := range cgroups {
		if cg == 12345 {
			t.Error("Cgroup 12345 should not be in blocked list after unblock")
		}
	}
}

func TestNFTablesManager_BlockIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{
			name: "IPv4",
			ip:   "192.0.2.1",
		},
		{
			name: "IPv6",
			ip:   "2001:db8::1",
		},
		{
			name:    "Invalid IP",
			ip:      "not-an-ip",
			wantErr: true,
		},
		{
			name:    "Empty IP",
			ip:      "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.BlockIP(ctx, tt.ip)
			if tt.wantErr {
				if err == nil {
					t.Errorf("BlockIP(%q) expected error, got nil", tt.ip)
				}
				return
			}
			if err != nil {
				t.Errorf("BlockIP(%q) failed: %v", tt.ip, err)
			}
		})
	}
}

func TestNFTablesManager_UnblockIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// Block then unblock
	if err := mgr.BlockIP(ctx, "192.0.2.1"); err != nil {
		t.Fatalf("BlockIP failed: %v", err)
	}

	if err := mgr.UnblockIP(ctx, "192.0.2.1"); err != nil {
		t.Errorf("UnblockIP failed: %v", err)
	}

	// Check that it's no longer in the blocked list
	ips := mgr.GetBlockedIPs()
	for _, ip := range ips {
		if ip == "192.0.2.1" {
			t.Error("IP 192.0.2.1 should not be in blocked list after unblock")
		}
	}
}

func TestNFTablesManager_Cleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// Add some blocks
	mgr.BlockUID(ctx, 1000)
	mgr.BlockUID(ctx, 1001)
	mgr.BlockCgroup(ctx, 12345)
	mgr.BlockIP(ctx, "192.0.2.1")

	// Cleanup
	if err := mgr.Cleanup(); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	// All lists should be empty
	if len(mgr.GetBlockedUIDs()) != 0 {
		t.Error("UID list should be empty after cleanup")
	}
	if len(mgr.GetBlockedCgroups()) != 0 {
		t.Error("Cgroup list should be empty after cleanup")
	}
	if len(mgr.GetBlockedIPs()) != 0 {
		t.Error("IP list should be empty after cleanup")
	}
}

func TestIsNFTablesAvailable(t *testing.T) {
	// This test just ensures the function doesn't panic
	// Actual availability depends on the system
	available := IsNFTablesAvailable()
	t.Logf("nftables available: %v", available)
}

func TestNFTablesManager_GetBackendName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	if name := mgr.GetBackendName(); name != "nftables" {
		t.Errorf("expected backend name 'nftables', got %s", name)
	}
}

func TestNFTablesManager_MultipleBlocks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun:    true,
		TableName: "test-ebpf-guard",
	})
	if err != nil {
		t.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	// Block multiple UIDs
	uids := []uint32{1000, 1001, 1002, 1003, 1004}
	for _, uid := range uids {
		if err := mgr.BlockUID(ctx, uid); err != nil {
			t.Errorf("BlockUID(%d) failed: %v", uid, err)
		}
	}

	// Verify all are blocked
	blockedUIDs := mgr.GetBlockedUIDs()
	if len(blockedUIDs) != len(uids) {
		t.Errorf("expected %d blocked UIDs, got %d", len(uids), len(blockedUIDs))
	}

	// Block multiple IPs
	ips := []string{"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"}
	for _, ip := range ips {
		if err := mgr.BlockIP(ctx, ip); err != nil {
			t.Errorf("BlockIP(%s) failed: %v", ip, err)
		}
	}

	blockedIPs := mgr.GetBlockedIPs()
	if len(blockedIPs) != len(ips) {
		t.Errorf("expected %d blocked IPs, got %d", len(ips), len(blockedIPs))
	}
}

// BenchmarkBlockUID benchmarks UID blocking.
func BenchmarkBlockUID(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun: true,
	})
	if err != nil {
		b.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		uid := uint32(i % 10000)
		mgr.BlockUID(ctx, uid)
	}
}

// BenchmarkBlockIP benchmarks IP blocking.
func BenchmarkBlockIP(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	mgr, err := NewNFTablesManager(logger, NFTablesConfig{
		DryRun: true,
	})
	if err != nil {
		b.Fatalf("NewNFTablesManager failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		mgr.BlockIP(ctx, ip)
	}
}
