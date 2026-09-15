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
