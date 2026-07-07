package enforcer

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
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

// ----------------------------------------------------------------------------
// Real-mode (non-dry-run) integration tests against the container's real
// iptables/ip6tables + nf_tables stack. Every test uses a unique chain name
// and cleans up via t.Cleanup so a failing assertion never leaks kernel state.
// ----------------------------------------------------------------------------

// realChainName derives a unique, length-safe (<=28 char), charset-safe chain
// name from the test name. iptables chain names are limited to ~28 chars.
func realChainName(t *testing.T) string {
	t.Helper()
	h := fnv.New32a()
	_, _ = h.Write([]byte(t.Name()))
	// "EG" prefix + 8 hex digits = 10 chars, well under the limit.
	name := "EG" + strings.ToUpper(hex32(h.Sum32()))
	return name
}

func hex32(v uint32) string {
	const digits = "0123456789ABCDEF"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = digits[v&0xf]
		v >>= 4
	}
	return string(b)
}

// newRealIPT constructs a real (non-dry-run) manager on a unique chain and
// registers Cleanup immediately so no assertion failure can leak a chain.
func newRealIPT(t *testing.T) (*IPTablesManager, string) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("real iptables tests require root")
	}
	chain := realChainName(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mgr, err := NewIPTablesManager(logger, IPTablesConfig{DryRun: false, ChainName: chain})
	if err != nil {
		t.Fatalf("NewIPTablesManager(real): %v", err)
	}
	t.Cleanup(func() {
		if err := mgr.Cleanup(); err != nil {
			t.Errorf("Cleanup: %v", err)
		}
	})
	return mgr, chain
}

// dumpChain returns the raw `-S <chain>` output for the filter table (v4).
func dumpChain(t *testing.T, binary, chain string) (string, error) {
	t.Helper()
	out, err := exec.Command(binary, "-t", "filter", "-S", chain).CombinedOutput()
	return string(out), err
}

func TestIPTablesManager_Real_NewManager(t *testing.T) {
	mgr, chain := newRealIPT(t)

	if !mgr.IsAvailable() {
		t.Fatal("IsAvailable() = false, want true (real binaries present)")
	}
	if mgr.GetBackendName() != "iptables" {
		t.Errorf("GetBackendName = %q, want iptables", mgr.GetBackendName())
	}
	if mgr.iptablesPath == "" {
		t.Error("iptablesPath was not auto-populated")
	}
	if mgr.ip6tablesPath == "" {
		t.Error("ip6tablesPath was not auto-populated")
	}

	// The dedicated chain must exist.
	if out, err := dumpChain(t, "iptables", chain); err != nil {
		t.Fatalf("chain %s not created: %v\n%s", chain, err, out)
	} else if !strings.Contains(out, "-N "+chain) {
		t.Errorf("chain listing missing -N %s:\n%s", chain, out)
	}

	// The OUTPUT jump rule must exist.
	out, err := exec.Command("iptables", "-t", "filter", "-S", "OUTPUT").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S OUTPUT: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "-j "+chain) {
		t.Errorf("OUTPUT missing jump to %s:\n%s", chain, out)
	}

	// v6 chain + jump too.
	out6, err := exec.Command("ip6tables", "-t", "filter", "-S", "OUTPUT").CombinedOutput()
	if err != nil {
		t.Fatalf("ip6tables -S OUTPUT: %v\n%s", err, out6)
	}
	if !strings.Contains(string(out6), "-j "+chain) {
		t.Errorf("ip6 OUTPUT missing jump to %s:\n%s", chain, out6)
	}
}

// TestIPTablesManager_Real_InitChainIdempotent constructs a manager twice on
// the SAME chain. The second construction must hit the "chain already exists"
// tolerance branch (-N) and the "jump rule already present" skip branch (-C).
func TestIPTablesManager_Real_InitChainIdempotent(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("real iptables tests require root")
	}
	chain := realChainName(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	mgr1, err := NewIPTablesManager(logger, IPTablesConfig{ChainName: chain})
	if err != nil {
		t.Fatalf("first NewIPTablesManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr1.Cleanup() })

	// Second construction on the same chain must succeed without error.
	mgr2, err := NewIPTablesManager(logger, IPTablesConfig{ChainName: chain})
	if err != nil {
		t.Fatalf("second NewIPTablesManager (idempotent) returned error: %v", err)
	}
	t.Cleanup(func() { _ = mgr2.Cleanup() })

	// There must be exactly ONE jump rule in OUTPUT (the -C check prevented a
	// duplicate insertion).
	out, err := exec.Command("iptables", "-t", "filter", "-S", "OUTPUT").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S OUTPUT: %v\n%s", err, out)
	}
	n := strings.Count(string(out), "-A OUTPUT -j "+chain)
	if n != 1 {
		t.Errorf("expected exactly 1 OUTPUT jump to %s, got %d:\n%s", chain, n, out)
	}
}

func TestIPTablesManager_Real_BlockUnblockUID(t *testing.T) {
	mgr, chain := newRealIPT(t)
	ctx := context.Background()

	const uid = uint32(65000)
	if err := mgr.BlockUID(ctx, uid); err != nil {
		t.Fatalf("BlockUID: %v", err)
	}

	// The owner DROP rule must be present in the v4 chain.
	v4, err := dumpChain(t, "iptables", chain)
	if err != nil {
		t.Fatalf("dump v4 chain: %v", err)
	}
	if !strings.Contains(v4, "--uid-owner 65000 -j DROP") {
		t.Errorf("v4 chain missing uid DROP rule:\n%s", v4)
	}
	// And mirrored on the v6 side (owner match is supported in this env).
	v6, err := dumpChain(t, "ip6tables", chain)
	if err != nil {
		t.Fatalf("dump v6 chain: %v", err)
	}
	if !strings.Contains(v6, "--uid-owner 65000 -j DROP") {
		t.Errorf("v6 chain missing uid DROP rule:\n%s", v6)
	}

	if got := mgr.GetBlockedUIDs(); len(got) != 1 || got[0] != uid {
		t.Errorf("GetBlockedUIDs = %v, want [65000]", got)
	}

	// Idempotent re-block is a no-op and must not add a second rule.
	if err := mgr.BlockUID(ctx, uid); err != nil {
		t.Fatalf("BlockUID (idempotent): %v", err)
	}
	v4again, _ := dumpChain(t, "iptables", chain)
	if c := strings.Count(v4again, "--uid-owner 65000 -j DROP"); c != 1 {
		t.Errorf("expected 1 uid DROP rule after re-block, got %d", c)
	}

	// Unblock and verify the real rule is gone from both tables.
	if err := mgr.UnblockUID(ctx, uid); err != nil {
		t.Fatalf("UnblockUID: %v", err)
	}
	v4, _ = dumpChain(t, "iptables", chain)
	if strings.Contains(v4, "--uid-owner 65000") {
		t.Errorf("v4 uid rule still present after unblock:\n%s", v4)
	}
	v6, _ = dumpChain(t, "ip6tables", chain)
	if strings.Contains(v6, "--uid-owner 65000") {
		t.Errorf("v6 uid rule still present after unblock:\n%s", v6)
	}
	if n := len(mgr.GetBlockedUIDs()); n != 0 {
		t.Errorf("expected 0 blocked UIDs after unblock, got %d", n)
	}

	// Unblocking a UID that was never blocked is a no-op.
	if err := mgr.UnblockUID(ctx, 12345); err != nil {
		t.Errorf("UnblockUID(not blocked): %v", err)
	}
}

func TestIPTablesManager_Real_BlockUnblockIP(t *testing.T) {
	mgr, chain := newRealIPT(t)
	ctx := context.Background()

	// IPv4 (TEST-NET-3, never routable) via iptables.
	const v4ip = "203.0.113.5"
	if err := mgr.BlockIP(ctx, v4ip); err != nil {
		t.Fatalf("BlockIP(v4): %v", err)
	}
	v4, err := dumpChain(t, "iptables", chain)
	if err != nil {
		t.Fatalf("dump v4 chain: %v", err)
	}
	if !strings.Contains(v4, "-d 203.0.113.5/32 -j DROP") {
		t.Errorf("v4 chain missing IP DROP rule:\n%s", v4)
	}

	// IPv6 (documentation range) via ip6tables.
	const v6ip = "2001:db8::5"
	if err := mgr.BlockIP(ctx, v6ip); err != nil {
		t.Fatalf("BlockIP(v6): %v", err)
	}
	v6, err := dumpChain(t, "ip6tables", chain)
	if err != nil {
		t.Fatalf("dump v6 chain: %v", err)
	}
	if !strings.Contains(v6, "-d 2001:db8::5/128 -j DROP") {
		t.Errorf("v6 chain missing IP DROP rule:\n%s", v6)
	}

	// The v6 rule must NOT be in the v4 chain (binaryForIP routed correctly).
	if strings.Contains(v4, "2001:db8") {
		t.Errorf("v6 address leaked into v4 chain:\n%s", v4)
	}

	// Idempotent re-block.
	if err := mgr.BlockIP(ctx, v4ip); err != nil {
		t.Fatalf("BlockIP(v4 idempotent): %v", err)
	}
	v4again, _ := dumpChain(t, "iptables", chain)
	if c := strings.Count(v4again, "-d 203.0.113.5/32 -j DROP"); c != 1 {
		t.Errorf("expected 1 v4 IP DROP rule after re-block, got %d", c)
	}

	// Unblock both and verify gone.
	if err := mgr.UnblockIP(ctx, v4ip); err != nil {
		t.Fatalf("UnblockIP(v4): %v", err)
	}
	if err := mgr.UnblockIP(ctx, v6ip); err != nil {
		t.Fatalf("UnblockIP(v6): %v", err)
	}
	v4, _ = dumpChain(t, "iptables", chain)
	if strings.Contains(v4, "203.0.113.5") {
		t.Errorf("v4 IP rule still present after unblock:\n%s", v4)
	}
	v6, _ = dumpChain(t, "ip6tables", chain)
	if strings.Contains(v6, "2001:db8::5") {
		t.Errorf("v6 IP rule still present after unblock:\n%s", v6)
	}

	// Invalid IP is rejected before touching the kernel.
	if err := mgr.BlockIP(ctx, "not-an-ip"); err == nil {
		t.Error("BlockIP(invalid) should error")
	}
	if err := mgr.UnblockIP(ctx, "not-an-ip"); err == nil {
		t.Error("UnblockIP(invalid) should error")
	}
}

// TestIPTablesManager_Real_Cleanup blocks a few entries, calls Cleanup, and
// asserts the real kernel state: OUTPUT jump gone and the chain deleted.
func TestIPTablesManager_Real_Cleanup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("real iptables tests require root")
	}
	chain := realChainName(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mgr, err := NewIPTablesManager(logger, IPTablesConfig{ChainName: chain})
	if err != nil {
		t.Fatalf("NewIPTablesManager: %v", err)
	}
	// Safety-net cleanup in case an assertion fails before the explicit call.
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = mgr.Cleanup()
		}
	})

	ctx := context.Background()
	_ = mgr.BlockUID(ctx, 65001)
	_ = mgr.BlockIP(ctx, "203.0.113.6")
	_ = mgr.BlockIP(ctx, "2001:db8::6")

	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	cleaned = true

	// OUTPUT jump must be gone (v4 and v6).
	for _, bin := range []string{"iptables", "ip6tables"} {
		out, err := exec.Command(bin, "-t", "filter", "-S", "OUTPUT").CombinedOutput()
		if err != nil {
			t.Fatalf("%s -S OUTPUT: %v\n%s", bin, err, out)
		}
		if strings.Contains(string(out), "-j "+chain) {
			t.Errorf("%s OUTPUT still has jump to %s after Cleanup:\n%s", bin, chain, out)
		}
		// The chain itself must no longer exist.
		out, err = exec.Command(bin, "-t", "filter", "-S", chain).CombinedOutput()
		if err == nil {
			t.Errorf("%s chain %s still exists after Cleanup:\n%s", bin, chain, out)
		}
	}

	// In-memory state is cleared too.
	if n := len(mgr.GetBlockedUIDs()); n != 0 {
		t.Errorf("blocked UIDs not cleared: %d", n)
	}
	if n := len(mgr.GetBlockedIPs()); n != 0 {
		t.Errorf("blocked IPs not cleared: %d", n)
	}
}

// ----------------------------------------------------------------------------
// Pure unit tests on unexported helpers (hand-constructed managers, in-package).
// ----------------------------------------------------------------------------

func Test_binaryForIP_Unit(t *testing.T) {
	// Zero-value manager: neither binary available → both lookups error.
	empty := &IPTablesManager{}
	if _, err := empty.binaryForIP(net.ParseIP("1.2.3.4")); err == nil {
		t.Error("binaryForIP(v4) with no iptables should error")
	}
	if _, err := empty.binaryForIP(net.ParseIP("::1")); err == nil {
		t.Error("binaryForIP(v6) with no ip6tables should error")
	}

	// Both available → correct binary per family.
	both := &IPTablesManager{iptablesPath: "/usr/sbin/iptables", ip6tablesPath: "/usr/sbin/ip6tables"}
	if got, err := both.binaryForIP(net.ParseIP("203.0.113.9")); err != nil || got != "/usr/sbin/iptables" {
		t.Errorf("binaryForIP(v4) = %q, %v; want iptables path", got, err)
	}
	if got, err := both.binaryForIP(net.ParseIP("2001:db8::9")); err != nil || got != "/usr/sbin/ip6tables" {
		t.Errorf("binaryForIP(v6) = %q, %v; want ip6tables path", got, err)
	}

	// Only v6 available → v4 request errors, v6 request succeeds.
	onlyV6 := &IPTablesManager{ip6tablesPath: "/usr/sbin/ip6tables"}
	if _, err := onlyV6.binaryForIP(net.ParseIP("1.2.3.4")); err == nil {
		t.Error("binaryForIP(v4) with only ip6tables should error")
	}
	if _, err := onlyV6.binaryForIP(net.ParseIP("2001:db8::1")); err != nil {
		t.Errorf("binaryForIP(v6) with ip6tables should succeed: %v", err)
	}
}

func Test_availableBinaries_Unit(t *testing.T) {
	if got := (&IPTablesManager{}).availableBinaries(); len(got) != 0 {
		t.Errorf("zero-value availableBinaries = %v, want empty", got)
	}
	if got := (&IPTablesManager{iptablesPath: "/a"}).availableBinaries(); len(got) != 1 || got[0] != "/a" {
		t.Errorf("v4-only availableBinaries = %v, want [/a]", got)
	}
	if got := (&IPTablesManager{ip6tablesPath: "/b"}).availableBinaries(); len(got) != 1 || got[0] != "/b" {
		t.Errorf("v6-only availableBinaries = %v, want [/b]", got)
	}
	got := (&IPTablesManager{iptablesPath: "/a", ip6tablesPath: "/b"}).availableBinaries()
	if len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Errorf("both availableBinaries = %v, want [/a /b] in order", got)
	}
}

func Test_run_Unit(t *testing.T) {
	m := &IPTablesManager{}
	ctx := context.Background()

	// A binary that exits 0 returns nil.
	if err := m.run(ctx, "/bin/echo", "hello"); err != nil {
		t.Errorf("run(/bin/echo) = %v, want nil", err)
	}

	// A binary that exits 1 returns a non-nil, ExitError-wrapping error.
	err := m.run(ctx, "/bin/false")
	if err == nil {
		t.Fatal("run(/bin/false) = nil, want error")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Errorf("run(/bin/false) error %v does not wrap *exec.ExitError", err)
	}

	// A nonexistent binary also errors.
	if err := m.run(ctx, "/nonexistent/binary/xyz"); err == nil {
		t.Error("run(nonexistent) = nil, want error")
	}
}

// TestIsIPTablesAvailable_True strengthens the trivial check: in THIS
// environment the iptables binary is known to exist.
func TestIsIPTablesAvailable_True(t *testing.T) {
	if !IsIPTablesAvailable() {
		t.Error("IsIPTablesAvailable() = false, but iptables is installed here")
	}
}
