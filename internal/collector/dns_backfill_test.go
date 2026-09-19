package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// fakeDNSSocketMap is an in-memory stand-in for *ebpf.Map, following the
// same pattern network_blocklist_test.go uses for bpfMap — cilium/ebpf
// cannot create a real map outside Linux.
type fakeDNSSocketMap struct {
	updates []dnsSocketKey
	failFor map[dnsSocketKey]bool
}

func (f *fakeDNSSocketMap) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	k := key.(dnsSocketKey)
	if f.failFor[k] {
		return os.ErrInvalid
	}
	f.updates = append(f.updates, k)
	return nil
}

func TestConnectedPort53Inodes(t *testing.T) {
	content := "" +
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n" +
		"   0: 00000000:8A3C 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 10001 2 0000000000000000 0\n" + // connected to :53
		"   1: 00000000:C001 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 10002 2 0000000000000000 0\n" + // not connected
		"   2: 00000000:A1B2 0101017F:00A0 01 00000000:00000000 00:00000000 00000000     0        0 10003 2 0000000000000000 0\n" + // connected, wrong port
		"   3: 00000000:B4D5 08080404:0035 01 00000000:00000000 00:00000000 00000000     0        0 10004 2 0000000000000000 0\n" // second :53 socket
	path := filepath.Join(t.TempDir(), "udp")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	inodes, err := connectedPort53Inodes(path)
	if err != nil {
		t.Fatalf("connectedPort53Inodes: %v", err)
	}
	want := map[string]struct{}{"10001": {}, "10004": {}}
	if len(inodes) != len(want) {
		t.Fatalf("got %v, want %v", inodes, want)
	}
	for k := range want {
		if _, ok := inodes[k]; !ok {
			t.Errorf("missing inode %s in %v", k, inodes)
		}
	}
}

// Wave 6.3 item 2 (plan.md, ревизия 19.09.2026, finding №383): /proc/net/udp6
// uses the same column layout as udp, with the address written as a
// continuous 32-hex-digit string (no colons inside it) rather than standard
// IPv6 notation — this fixture is a real sample shape, not a simplification.
func TestConnectedPort53Inodes_UDP6(t *testing.T) {
	content := "" +
		"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n" +
		"   0: 00000000000000000000000000000000:C7B4 20010DB8000000000000000000000001:0035 01 00000000:00000000 00:00000000 00000000     0        0 40001 2 0000000000000000 0\n" + // connected to [::53] equivalent
		"   1: 00000000000000000000000000000000:9E10 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 40002 2 0000000000000000 0\n" // not connected
	path := filepath.Join(t.TempDir(), "udp6")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	inodes, err := connectedPort53Inodes(path)
	if err != nil {
		t.Fatalf("connectedPort53Inodes(udp6): %v", err)
	}
	if len(inodes) != 1 {
		t.Fatalf("got %v, want exactly {40001}", inodes)
	}
	if _, ok := inodes["40001"]; !ok {
		t.Errorf("missing inode 40001 in %v", inodes)
	}
}

// A namespace where net/udp6 is absent (IPv6 disabled in the kernel) must
// not affect the IPv4-only result — best-effort, same as an unreadable udp
// table.
func TestConnectedPort53InodesAllNamespaces_NoUDP6IsFine(t *testing.T) {
	hostUDP := "   0: 00000000:8A3C 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 50001 2 0000000000000000 0\n"
	root := fakeNamespacedProcTree(t, map[string]struct {
		ns      string
		udpBody string
	}{
		"1": {ns: "4026531840", udpBody: hostUDP},
	})

	inodes, err := connectedPort53InodesAllNamespaces(root)
	if err != nil {
		t.Fatalf("connectedPort53InodesAllNamespaces: %v", err)
	}
	if len(inodes) != 1 {
		t.Fatalf("got %v, want exactly {50001}", inodes)
	}
}

// The union of udp and udp6 for the same namespace must include inodes
// from both — the actual behaviour finding №383 adds.
func TestConnectedPort53InodesAllNamespaces_UnionsUDPAndUDP6(t *testing.T) {
	root := t.TempDir()
	nsDir := filepath.Join(root, "1", "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026531840]", filepath.Join(nsDir, "net")); err != nil {
		t.Fatal(err)
	}
	netDir := filepath.Join(root, "1", "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	udpBody := "   0: 00000000:8A3C 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 60001 2 0000000000000000 0\n"
	udp6Body := "   0: 00000000000000000000000000000000:C7B4 20010DB8000000000000000000000001:0035 01 00000000:00000000 00:00000000 00000000     0        0 60002 2 0000000000000000 0\n"
	if err := os.WriteFile(filepath.Join(netDir, "udp"), []byte(header+udpBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "udp6"), []byte(header+udp6Body), 0o644); err != nil {
		t.Fatal(err)
	}

	inodes, err := connectedPort53InodesAllNamespaces(root)
	if err != nil {
		t.Fatalf("connectedPort53InodesAllNamespaces: %v", err)
	}
	want := map[string]struct{}{"60001": {}, "60002": {}}
	if len(inodes) != len(want) {
		t.Fatalf("got %v, want %v", inodes, want)
	}
	for k := range want {
		if _, ok := inodes[k]; !ok {
			t.Errorf("missing inode %s in %v", k, inodes)
		}
	}
}

func TestConnectedPort53Inodes_MissingFile(t *testing.T) {
	if _, err := connectedPort53Inodes(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// fakeProcTree builds a directory tree under a temp dir shaped like
// <root>/<pid>/fd/<fd> -> socket:[<inode>], plus a non-pid entry and a
// dangling entry, to exercise the filtering the real /proc walk relies on.
func fakeProcTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	mk := func(pid, fd string, target string) {
		dir := filepath.Join(root, pid, "fd")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, fd)); err != nil {
			t.Fatal(err)
		}
	}

	mk("100", "3", "socket:[10001]") // matches
	mk("100", "4", "socket:[99999]") // non-DNS socket, no match
	mk("100", "5", "/dev/null")      // not a socket at all
	mk("200", "6", "socket:[10004]") // matches, different process
	// non-pid directory (e.g. "self", "thread-self") must be skipped
	if err := os.MkdirAll(filepath.Join(root, "self", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[10001]", filepath.Join(root, "self", "fd", "3")); err != nil {
		t.Fatal(err)
	}

	return root
}

func TestSeedSocketMapFromProcFDs(t *testing.T) {
	root := fakeProcTree(t)
	inodes := map[string]struct{}{"10001": {}, "10004": {}}
	m := &fakeDNSSocketMap{}

	n, err := seedSocketMapFromProcFDs(m, root, inodes)
	if err != nil {
		t.Fatalf("seedSocketMapFromProcFDs: %v", err)
	}
	if n != 2 {
		t.Fatalf("got %d seeded entries, want 2 (updates=%v)", n, m.updates)
	}
	want := map[dnsSocketKey]bool{
		{Tgid: 100, Fd: 3}: true,
		{Tgid: 200, Fd: 6}: true,
	}
	if len(m.updates) != len(want) {
		t.Fatalf("updates=%v, want keys %v", m.updates, want)
	}
	for _, k := range m.updates {
		if !want[k] {
			t.Errorf("unexpected key seeded: %+v", k)
		}
	}
}

func TestSeedSocketMapFromProcFDs_NoMatches(t *testing.T) {
	root := fakeProcTree(t)
	m := &fakeDNSSocketMap{}

	n, err := seedSocketMapFromProcFDs(m, root, map[string]struct{}{"nope": {}})
	if err != nil {
		t.Fatalf("seedSocketMapFromProcFDs: %v", err)
	}
	if n != 0 {
		t.Fatalf("got %d, want 0", n)
	}
}

func TestSeedSocketMapFromProcFDs_UpdateFailureSkipped(t *testing.T) {
	root := fakeProcTree(t)
	inodes := map[string]struct{}{"10001": {}, "10004": {}}
	m := &fakeDNSSocketMap{failFor: map[dnsSocketKey]bool{{Tgid: 100, Fd: 3}: true}}

	n, err := seedSocketMapFromProcFDs(m, root, inodes)
	if err != nil {
		t.Fatalf("seedSocketMapFromProcFDs: %v", err)
	}
	if n != 1 {
		t.Fatalf("got %d, want 1 (one Update failed and should be skipped, not fatal)", n)
	}
}

// fakeNamespacedProcTree builds <root>/<pid>/ns/net -> ns:[<nsInode>] and
// <root>/<pid>/net/udp shaped like the fixture in TestConnectedPort53Inodes,
// so connectedPort53InodesAllNamespaces can be exercised against several
// pids sharing and not sharing namespaces without a real kernel.
func fakeNamespacedProcTree(t *testing.T, pids map[string]struct {
	ns      string
	udpBody string
}) string {
	t.Helper()
	root := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	for pid, spec := range pids {
		nsDir := filepath.Join(root, pid, "ns")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("net:["+spec.ns+"]", filepath.Join(nsDir, "net")); err != nil {
			t.Fatal(err)
		}
		netDir := filepath.Join(root, pid, "net")
		if err := os.MkdirAll(netDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(netDir, "udp"), []byte(header+spec.udpBody), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestConnectedPort53InodesAllNamespaces_DedupsByNamespace(t *testing.T) {
	hostUDP := "   0: 00000000:8A3C 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 20001 2 0000000000000000 0\n"
	podUDP := "   0: 00000000:9000 08080404:0035 01 00000000:00000000 00:00000000 00000000     0        0 20002 2 0000000000000000 0\n"
	root := fakeNamespacedProcTree(t, map[string]struct {
		ns      string
		udpBody string
	}{
		"1":   {ns: "4026531840", udpBody: hostUDP}, // host netns, PID 1
		"100": {ns: "4026531840", udpBody: hostUDP}, // shares host netns with PID 1 — must not be read twice
		"200": {ns: "4026532200", udpBody: podUDP},  // distinct pod netns
	})

	inodes, err := connectedPort53InodesAllNamespaces(root)
	if err != nil {
		t.Fatalf("connectedPort53InodesAllNamespaces: %v", err)
	}
	want := map[string]struct{}{"20001": {}, "20002": {}}
	if len(inodes) != len(want) {
		t.Fatalf("got %v, want %v", inodes, want)
	}
	for k := range want {
		if _, ok := inodes[k]; !ok {
			t.Errorf("missing inode %s in %v", k, inodes)
		}
	}
}

func TestConnectedPort53InodesAllNamespaces_SkipsUnreadableNamespace(t *testing.T) {
	root := t.TempDir()
	// PID 1: readable ns + udp table with one connected socket.
	hostUDP := "   0: 00000000:8A3C 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 30001 2 0000000000000000 0\n"
	nsDir := filepath.Join(root, "1", "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026531840]", filepath.Join(nsDir, "net")); err != nil {
		t.Fatal(err)
	}
	netDir := filepath.Join(root, "1", "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	if err := os.WriteFile(filepath.Join(netDir, "udp"), []byte(header+hostUDP), 0o644); err != nil {
		t.Fatal(err)
	}
	// PID 2: no ns/net symlink at all — simulates "exited between listing
	// and reading" or a permission failure; must be skipped, not fatal.
	if err := os.MkdirAll(filepath.Join(root, "2"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Non-pid entry must be skipped.
	if err := os.MkdirAll(filepath.Join(root, "self", "ns"), 0o755); err != nil {
		t.Fatal(err)
	}

	inodes, err := connectedPort53InodesAllNamespaces(root)
	if err != nil {
		t.Fatalf("connectedPort53InodesAllNamespaces: %v", err)
	}
	if len(inodes) != 1 {
		t.Fatalf("got %v, want exactly {30001}", inodes)
	}
	if _, ok := inodes["30001"]; !ok {
		t.Errorf("missing inode 30001 in %v", inodes)
	}
}

func TestBackfillDNSSocketMap_NoConnectedSockets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp")
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	if err := os.WriteFile(path, []byte(header), 0o644); err != nil {
		t.Fatal(err)
	}
	inodes, err := connectedPort53Inodes(path)
	if err != nil {
		t.Fatalf("connectedPort53Inodes: %v", err)
	}
	if len(inodes) != 0 {
		t.Fatalf("got %v, want empty", inodes)
	}
}

// Finding №386 (wave 6.3, ревизия 19.09.2026): a namespace was marked "seen"
// BEFORE its udp table was read, so a pid that vanished between the ns/net
// readlink and the table open blinded the whole namespace for the entire
// scan — no other process sharing it was ever tried. Here pid 1 has a net
// directory with no tables at all (the shape a vanished pid leaves), pid 2
// shares its namespace and has the table; the inode must still be found.
func TestConnectedPort53InodesAllNamespaces_RetriesNamespaceAfterUnreadablePid(t *testing.T) {
	root := t.TempDir()
	const ns = "net:[4026531840]"
	for _, pid := range []string{"1", "2"} {
		nsDir := filepath.Join(root, pid, "ns")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns, filepath.Join(nsDir, "net")); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, pid, "net"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	body := "   0: 00000000:8A3C 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 70001 2 0000000000000000 0\n"
	// Only pid 2 can serve the table. Readdirnames order is filesystem order,
	// not sorted, so this exercises the retry whenever pid 1 comes first — it
	// can never fail for the fixed code, and never passes for the old code in
	// that order. maxNSReadAttempts (3) leaves room for the second pid.
	if err := os.WriteFile(filepath.Join(root, "2", "net", "udp"), []byte(header+body), 0o644); err != nil {
		t.Fatal(err)
	}

	inodes, err := connectedPort53InodesAllNamespaces(root)
	if err != nil {
		t.Fatalf("connectedPort53InodesAllNamespaces: %v", err)
	}
	if _, ok := inodes["70001"]; !ok {
		t.Fatalf("got %v, want inode 70001 — an unreadable first pid must not "+
			"retire the namespace for the rest of the scan (finding №386)", inodes)
	}
}

// Finding №386, the other half: udp and udp6 are read independently, so a
// namespace whose udp table cannot be read still contributes its udp6 inodes.
func TestConnectedPort53InodesAllNamespaces_UDP6SurvivesUnreadableUDP(t *testing.T) {
	root := t.TempDir()
	nsDir := filepath.Join(root, "1", "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026531999]", filepath.Join(nsDir, "net")); err != nil {
		t.Fatal(err)
	}
	netDir := filepath.Join(root, "1", "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	udp6Body := "   0: 00000000000000000000000000000000:C7B4 20010DB8000000000000000000000001:0035 01 00000000:00000000 00:00000000 00000000     0        0 70002 2 0000000000000000 0\n"
	// net/udp deliberately absent; net/udp6 present.
	if err := os.WriteFile(filepath.Join(netDir, "udp6"), []byte(header+udp6Body), 0o644); err != nil {
		t.Fatal(err)
	}

	inodes, err := connectedPort53InodesAllNamespaces(root)
	if err != nil {
		t.Fatalf("connectedPort53InodesAllNamespaces: %v", err)
	}
	if _, ok := inodes["70002"]; !ok {
		t.Fatalf("got %v, want inode 70002 — an unreadable udp table must not "+
			"suppress udp6 for the same namespace (finding №386)", inodes)
	}
}
