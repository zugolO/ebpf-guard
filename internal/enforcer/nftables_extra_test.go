package enforcer

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// This file adds REAL (non-dry-run) nftables integration coverage on top of
// the dry-run-only tests in nftables_test.go. The container this test suite
// runs in has a working nftables netlink stack and root privileges, so these
// tests program real kernel rules and verify them via `nft list table`.

var nftTableSeq int64

// uniqueNFTTable returns a short, unique, nftables-safe table name derived
// from the test name plus an atomic counter (belt-and-braces beyond t.Name()
// alone, in case of subtests sharing a prefix).
func uniqueNFTTable(t *testing.T) string {
	t.Helper()
	n := atomic.AddInt64(&nftTableSeq, 1)
	suffix := fmt.Sprintf("-%d", n)
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, t.Name())
	// Reserve room for the "eg-" prefix and numeric suffix so the uniqueness
	// guarantee (the counter) is never itself truncated away.
	maxSafeLen := 30 - len("eg-") - len(suffix)
	if len(safe) > maxSafeLen {
		safe = safe[:maxSafeLen]
	}
	return fmt.Sprintf("eg-%s%s", safe, suffix)
}

// nftListTable returns `nft list table inet <name>` output, or "" if the
// table does not exist (nft exits non-zero in that case).
func nftListTable(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", name).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func newRealNFTManager(t *testing.T) (*NFTablesManager, string) {
	t.Helper()
	name := uniqueNFTTable(t)
	mgr, err := NewNFTablesManager(testLogger(), NFTablesConfig{TableName: name})
	if err != nil {
		t.Fatalf("NewNFTablesManager (real): %v", err)
	}
	t.Cleanup(func() { _ = mgr.Cleanup() })
	return mgr, name
}

func TestNFTablesManager_RealMode_CreatesTableAndChain(t *testing.T) {
	mgr, name := newRealNFTManager(t)
	if mgr.dryRun {
		t.Fatal("expected real (non-dry-run) manager")
	}
	out := nftListTable(t, name)
	if !strings.Contains(out, "chain output") {
		t.Errorf("expected an output chain in table %s, got:\n%s", name, out)
	}
}

func TestNFTablesManager_RealMode_InitializeIdempotent(t *testing.T) {
	name := uniqueNFTTable(t)
	mgr1, err := NewNFTablesManager(testLogger(), NFTablesConfig{TableName: name})
	if err != nil {
		t.Fatalf("first NewNFTablesManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr1.Cleanup() })

	// Second manager pointed at the SAME table must find the existing
	// table/chain (the "existingTable != nil" branch in initialize) rather
	// than erroring or duplicating it.
	mgr2, err := NewNFTablesManager(testLogger(), NFTablesConfig{TableName: name})
	if err != nil {
		t.Fatalf("second NewNFTablesManager (idempotent): %v", err)
	}
	if mgr2.table == nil || mgr2.outputChain == nil {
		t.Fatal("second manager should have found the existing table and output chain")
	}

	out, err := exec.Command("nft", "-j", "list", "tables").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list tables: %v", err)
	}
	count := strings.Count(string(out), `"name": "`+name+`"`)
	if count != 1 {
		t.Errorf("expected exactly 1 table named %q, found %d occurrences in:\n%s", name, count, out)
	}
}

func TestNFTablesManager_RealMode_BlockUnblockUID(t *testing.T) {
	mgr, name := newRealNFTManager(t)
	ctx := context.Background()

	const uid = 65001
	if err := mgr.BlockUID(ctx, uid); err != nil {
		t.Fatalf("BlockUID: %v", err)
	}
	out := nftListTable(t, name)
	if !strings.Contains(out, "meta skuid") || !strings.Contains(out, "drop") {
		t.Errorf("expected a meta skuid ... drop rule after BlockUID, got:\n%s", out)
	}
	if !strings.Contains(out, strconv.Itoa(uid)) {
		t.Errorf("expected rule to reference uid %d, got:\n%s", uid, out)
	}

	// UnblockUID scans real kernel rules via GetRules + isUIDRule and must
	// actually delete the matching one.
	if err := mgr.UnblockUID(ctx, uid); err != nil {
		t.Fatalf("UnblockUID: %v", err)
	}
	out = nftListTable(t, name)
	if strings.Contains(out, "meta skuid") {
		t.Errorf("expected UID rule to be gone after UnblockUID, got:\n%s", out)
	}
}

func TestNFTablesManager_RealMode_BlockUnblockIP_IPv4(t *testing.T) {
	mgr, name := newRealNFTManager(t)
	ctx := context.Background()

	const ip = "203.0.113.5" // TEST-NET-3, never routable
	if err := mgr.BlockIP(ctx, ip); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	out := nftListTable(t, name)
	if !strings.Contains(out, "drop") {
		t.Errorf("expected a drop rule after BlockIP(%s), got:\n%s", ip, out)
	}

	// Regression test for the isIPRule width-mismatch bug: an IPv4 rule's
	// Cmp.Data is 4 bytes, but net.ParseIP(ip) returns a 16-byte slice, so
	// without normalising by cmp.Data's length the rule would never be
	// found and UnblockIP would silently leave the kernel-level DROP in
	// place forever while still reporting success and removing it from
	// the in-memory blocklist.
	if err := mgr.UnblockIP(ctx, ip); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}
	out = nftListTable(t, name)
	if strings.Contains(out, "drop") {
		t.Errorf("expected IPv4 DROP rule to be removed from the kernel after UnblockIP, got:\n%s", out)
	}
	for _, blocked := range mgr.GetBlockedIPs() {
		if blocked == ip {
			t.Errorf("expected %s to be removed from in-memory blocklist", ip)
		}
	}
}

func TestNFTablesManager_RealMode_BlockUnblockIP_IPv6(t *testing.T) {
	mgr, name := newRealNFTManager(t)
	ctx := context.Background()

	const ip = "2001:db8::5" // documentation range
	if err := mgr.BlockIP(ctx, ip); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	out := nftListTable(t, name)
	if !strings.Contains(out, "drop") {
		t.Errorf("expected a drop rule after BlockIP(%s), got:\n%s", ip, out)
	}

	if err := mgr.UnblockIP(ctx, ip); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}
	out = nftListTable(t, name)
	if strings.Contains(out, "drop") {
		t.Errorf("expected IPv6 DROP rule to be removed after UnblockIP, got:\n%s", out)
	}
}

func TestNFTablesManager_RealMode_UnblockIP_OnlyRemovesMatch(t *testing.T) {
	mgr, name := newRealNFTManager(t)
	ctx := context.Background()

	const keep = "198.51.100.10"
	const drop = "198.51.100.20"
	if err := mgr.BlockIP(ctx, keep); err != nil {
		t.Fatalf("BlockIP(keep): %v", err)
	}
	if err := mgr.BlockIP(ctx, drop); err != nil {
		t.Fatalf("BlockIP(drop): %v", err)
	}

	if err := mgr.UnblockIP(ctx, drop); err != nil {
		t.Fatalf("UnblockIP(drop): %v", err)
	}

	// nft renders raw payload-match rules as hex (e.g. "0xc63364..."), not
	// dotted-decimal, so compare against the hex encoding of each IP.
	keepHex := fmt.Sprintf("0x%02x%02x%02x%02x", 198, 51, 100, 10)
	dropHex := fmt.Sprintf("0x%02x%02x%02x%02x", 198, 51, 100, 20)

	out := nftListTable(t, name)
	if !strings.Contains(out, keepHex) {
		t.Errorf("expected rule for %s (%s) to remain, got:\n%s", keep, keepHex, out)
	}
	if strings.Contains(out, dropHex) {
		t.Errorf("expected rule for %s (%s) to be gone, got:\n%s", drop, dropHex, out)
	}
}

func TestNFTablesManager_RealMode_Cleanup(t *testing.T) {
	name := uniqueNFTTable(t)
	mgr, err := NewNFTablesManager(testLogger(), NFTablesConfig{TableName: name})
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}
	ctx := context.Background()
	_ = mgr.BlockUID(ctx, 65002)
	_ = mgr.BlockIP(ctx, "192.0.2.77")

	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	out, err := exec.Command("nft", "list", "tables").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list tables: %v", err)
	}
	if strings.Contains(string(out), name) {
		t.Errorf("expected table %s to be gone after Cleanup, got:\n%s", name, out)
	}
	if len(mgr.GetBlockedUIDs()) != 0 || len(mgr.GetBlockedIPs()) != 0 {
		t.Error("expected in-memory blocklists to be empty after Cleanup")
	}
}

func TestIsNFTablesAvailable_RealEnvironment(t *testing.T) {
	if !IsNFTablesAvailable() {
		t.Fatal("expected nftables to be available in this test environment (root container with a working nf_tables netlink stack)")
	}
}

// --- isUIDRule / isIPRule pure unit tests (hand-constructed rules) ---------

func TestIsUIDRule_Unit(t *testing.T) {
	m := &NFTablesManager{}
	rule := &nftables.Rule{
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(4242)},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	}
	if !m.isUIDRule(rule, 4242) {
		t.Error("expected exact UID match to return true")
	}
	if m.isUIDRule(rule, 4243) {
		t.Error("expected non-matching UID to return false")
	}

	shortData := &nftables.Rule{
		Exprs: []expr.Any{&expr.Cmp{Register: 1, Data: []byte{1, 2}}},
	}
	if m.isUIDRule(shortData, 4242) {
		t.Error("expected wrong-length Cmp.Data to never match")
	}
}

func TestIsIPRule_Unit(t *testing.T) {
	m := &NFTablesManager{}

	v4 := net.ParseIP("192.0.2.55")
	v4Rule := &nftables.Rule{
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: v4.To4()},
		},
	}
	if !m.isIPRule(v4Rule, v4) {
		t.Error("expected IPv4 rule (4-byte Cmp.Data) to match a 16-byte net.ParseIP value")
	}
	if m.isIPRule(v4Rule, net.ParseIP("192.0.2.56")) {
		t.Error("expected non-matching IPv4 to return false")
	}

	v6 := net.ParseIP("2001:db8::99")
	v6Rule := &nftables.Rule{
		Exprs: []expr.Any{
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: v6.To16()},
		},
	}
	if !m.isIPRule(v6Rule, v6) {
		t.Error("expected IPv6 rule to match")
	}
	if m.isIPRule(v6Rule, net.ParseIP("2001:db8::100")) {
		t.Error("expected non-matching IPv6 to return false")
	}

	// A Cmp with a length that is neither 4 nor 16 must never match.
	oddRule := &nftables.Rule{
		Exprs: []expr.Any{&expr.Cmp{Register: 1, Data: []byte{9, 9, 9}}},
	}
	if m.isIPRule(oddRule, v4) {
		t.Error("expected odd-length Cmp.Data to never match")
	}
}

// --- cgroup: real cgroupv2 freeze + findCgroupPathByID ---------------------

// cgroupV2WritableRoot returns a real, writable cgroupv2 mount point this
// container can create sub-cgroups under, or "" if none is available.
// /sys/fs/cgroup itself is cgroupv1-per-controller in some containers, with
// a nested cgroupv2 mount (commonly at ".../unified") that DOES support
// cgroup.freeze on non-root sub-cgroups.
func cgroupV2WritableRoot(t *testing.T) string {
	t.Helper()
	candidates := []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"}
	for _, root := range candidates {
		if _, err := os.Stat(root + "/cgroup.controllers"); err != nil {
			continue
		}
		probe := root + "/eg-probe-writable"
		if err := os.Mkdir(probe, 0o755); err != nil {
			continue
		}
		_ = os.Remove(probe)
		return root
	}
	return ""
}

func TestFindCgroupPathByID_Real(t *testing.T) {
	root := cgroupV2WritableRoot(t)
	if root == "" {
		t.Skip("no writable cgroupv2 hierarchy available in this environment")
	}

	dir := root + "/eg-findpath-test"
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })

	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatalf("stat: %v", err)
	}

	// findCgroupPathByID always walks the real /sys/fs/cgroup root.
	found, err := findCgroupPathByID(st.Ino)
	if root == "/sys/fs/cgroup" {
		if err != nil {
			t.Fatalf("findCgroupPathByID: %v", err)
		}
		if found != dir {
			t.Errorf("findCgroupPathByID = %q, want %q", found, dir)
		}
	} else if err == nil && found != dir {
		// The nested-unified root case still lives under /sys/fs/cgroup, so
		// the walk should still discover it.
		t.Errorf("findCgroupPathByID = %q, want %q", found, dir)
	}
}

func TestFindCgroupPathByID_Real_NotFound(t *testing.T) {
	_, err := findCgroupPathByID(0xDEADBEEFDEADBEEF)
	if err == nil {
		t.Error("expected error for a cgroup ID that cannot exist")
	}
}

func TestNFTablesManager_RealMode_BlockUnblockCgroup_Freeze(t *testing.T) {
	root := cgroupV2WritableRoot(t)
	if root == "" {
		t.Skip("no writable cgroupv2 hierarchy available in this environment")
	}

	dir := root + "/eg-blockcgroup-test"
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })

	if _, err := os.Stat(dir + "/cgroup.freeze"); err != nil {
		t.Skip("cgroup.freeze not available for a fresh sub-cgroup in this environment")
	}

	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatalf("stat: %v", err)
	}
	cgroupID := st.Ino

	mgr, _ := newRealNFTManager(t)
	ctx := context.Background()

	if err := mgr.BlockCgroup(ctx, cgroupID); err != nil {
		t.Fatalf("BlockCgroup: %v", err)
	}

	// The freeze half is only exercised if findCgroupPathByID (which always
	// scans the real /sys/fs/cgroup root) actually located our directory.
	if root == "/sys/fs/cgroup" {
		got, err := os.ReadFile(dir + "/cgroup.freeze")
		if err != nil {
			t.Fatalf("read cgroup.freeze: %v", err)
		}
		if strings.TrimSpace(string(got)) != "1" {
			t.Errorf("cgroup.freeze = %q after BlockCgroup, want \"1\"", strings.TrimSpace(string(got)))
		}
	}

	cgroups := mgr.GetBlockedCgroups()
	found := false
	for _, cg := range cgroups {
		if cg == cgroupID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cgroup %d in GetBlockedCgroups()", cgroupID)
	}

	if err := mgr.UnblockCgroup(ctx, cgroupID); err != nil {
		t.Fatalf("UnblockCgroup: %v", err)
	}

	if root == "/sys/fs/cgroup" {
		got, err := os.ReadFile(dir + "/cgroup.freeze")
		if err != nil {
			t.Fatalf("read cgroup.freeze after unblock: %v", err)
		}
		if strings.TrimSpace(string(got)) != "0" {
			t.Errorf("cgroup.freeze = %q after UnblockCgroup, want \"0\"", strings.TrimSpace(string(got)))
		}
	}
}

func TestNFTablesManager_RealMode_AddRemoveCgroupDropRule(t *testing.T) {
	mgr, name := newRealNFTManager(t)

	const cgroupID = uint64(999888777)
	if err := mgr.addCgroupDropRule(cgroupID); err != nil {
		t.Fatalf("addCgroupDropRule: %v", err)
	}
	out := nftListTable(t, name)
	if !strings.Contains(out, "drop") {
		t.Errorf("expected a drop rule after addCgroupDropRule, got:\n%s", out)
	}

	if err := mgr.removeCgroupDropRule(cgroupID); err != nil {
		t.Fatalf("removeCgroupDropRule: %v", err)
	}
	out = nftListTable(t, name)
	if strings.Contains(out, "drop") {
		t.Errorf("expected drop rule to be removed, got:\n%s", out)
	}
}
