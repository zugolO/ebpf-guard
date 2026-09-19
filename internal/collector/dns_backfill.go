package collector

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// dnsSocketKey is the BPF key for dns_socket_map (BPF_MAP_TYPE_LRU_HASH).
// Layout must match struct dns_socket_key in bpf/dns.bpf.c exactly: two
// adjacent __u32 fields, no padding.
type dnsSocketKey struct {
	Tgid uint32
	Fd   uint32
}

// dnsSocketMapUpdater is the subset of *ebpf.Map used by the backfill —
// extracted so tests can inject an in-memory fake instead of a real BPF
// map, which cilium/ebpf cannot create outside Linux (network_blocklist.go
// takes the same approach for the same reason).
type dnsSocketMapUpdater interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

// backfillDNSSocketMap seeds dns_socket_map with UDP sockets that were
// already connect()ed to port 53 before this process started attaching
// tracepoints.
//
// Why this exists (finding №328, plan.md §6.3). trace_connect is the only
// path that populates dns_socket_map, and it only fires on this agent's
// watch. A resolver that opened its upstream socket before the agent
// started — coredns is the daemon case on the test node, but any
// long-lived process holding a connected UDP:53 socket has the same shape
// — never crosses trace_connect, so every later sendmmsg()/recvmsg()/
// write()/read() on that fd stays permanently invisible to
// is_dns_socket_fd, even though a fresh one-shot query on a new fd would
// have been caught directly by trace_sendmsg/trace_sendto (those carry an
// explicit destination address and do not consult the map at all). On a
// node running coredns this reads as near-total silence — 8 events/10min
// against a resolver that handles far more, found constant across 14
// archives — with every liveness signal green: dns_collector_stale stays
// 0 because the collector genuinely is attached and reading, it is just
// blind to sockets it never saw connect().
//
// This is a startup-only scan, not a running mechanism: it reads
// /proc/<pid>/net/udp once per distinct network namespace (finding №340 —
// the host's own /proc/net/udp only sees the host netns, and coredns's
// upstream socket lives inside the pod's netns and never appears there)
// for entries connected to remote port 53, matches their inodes against
// every process's open file descriptors, and inserts the resulting
// (tgid, fd) pairs directly — the same write trace_connect would have
// made had it been attached at the time. It cannot see a socket that
// connects during the scan itself (the window between listing
// /proc/<pid>/net/udp and attaching tracepoints); that residual race is
// the same one the collector always had for its own startup and is not
// new here.
//
// Wave 6.3 item 2 (plan.md, ревизия 19.09.2026): this scan also reads
// /proc/<pid>/net/udp6 (finding №383) and seeds dns_socket_map from it the
// same way. That closes a real, if partial, part of the IPv6 gap:
// is_dns_socket_fd (bpf/dns.bpf.c) gates read()/write()/sendmmsg() purely on
// fd membership in dns_socket_map, with no address-family check — a fd
// seeded here from an IPv6 socket is indistinguishable from one seeded off
// udp, and later traffic on it is parsed like any other. What this does NOT
// close, because it needs a BPF program change this offline pass cannot
// build or measure without a Linux stand: trace_connect (bpf/dns.bpf.c,
// ~line 100) filters sa_family==AF_INET before insertion, so a NEW IPv6
// connection made after this agent starts still never reaches
// dns_socket_map on its own — only a socket already connected at startup,
// caught by this scan, benefits. See dnsNonTransportBlindSpots in dns.go
// for the record of what remains open.
//
// candidates is the number of distinct connected-to-:53 socket inodes
// found across all namespaces, BEFORE matching them against process fds —
// finding №341: backfilled==0 alone cannot distinguish "nothing to seed"
// from "found sockets but failed to match/insert them", so the caller
// publishes candidates and backfilled as two separate counters.
func backfillDNSSocketMap(m dnsSocketMapUpdater) (candidates, backfilled int, err error) {
	inodes, err := connectedPort53InodesAllNamespaces("/proc")
	if err != nil {
		return 0, 0, fmt.Errorf("scan network namespaces under /proc: %w", err)
	}
	candidates = len(inodes)
	if candidates == 0 {
		return 0, 0, nil
	}
	n, err := seedSocketMapFromProcFDs(m, "/proc", inodes)
	return candidates, n, err
}

// connectedPort53InodesAllNamespaces returns the union of
// connectedPort53Inodes across every distinct network namespace reachable
// from procRoot, reading each namespace's udp and udp6 tables once
// regardless of how many processes share it (up to maxNSReadAttempts pids
// when the chosen pid's table could not be read at all). Socket inodes are allocated
// from the kernel's global anonymous-inode pool, not per-namespace, so
// inodes from different namespaces never collide when merged into one
// set — the same assumption seedSocketMapFromProcFDs already relies on
// when it matches these inodes against fds across ALL processes.
//
// A process that exits mid-scan, or whose ns/net this agent cannot read
// (permission, already gone), is skipped — same best-effort tolerance as
// seedSocketMapFromProcFDs.
func connectedPort53InodesAllNamespaces(procRoot string) (map[string]struct{}, error) {
	procDir, err := os.Open(procRoot)
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	names, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	// attempts counts how many pids were tried per network namespace, and
	// doneNS records the ones whose tables were actually read (or are known
	// absent). Finding №386 (wave 6.3, ревизия 19.09.2026): marking a
	// namespace seen BEFORE the read succeeded made one unlucky pid — one
	// that exited between the ns/net readlink and the table open — blind the
	// WHOLE namespace for the entire scan, even though every other process
	// sharing it would have served the same table. That is a resolver's
	// upstream socket silently missing from the backfill, which is exactly
	// the class of blindness this whole file exists to remove (№328/№340).
	// Retrying costs one open() per extra pid and is capped, so a namespace
	// this agent genuinely cannot read (permission, not running as root)
	// cannot turn into a scan of every pid on the node.
	attempts := make(map[string]int)
	doneNS := make(map[string]struct{})
	inodes := make(map[string]struct{})
	for _, name := range names {
		if _, err := strconv.ParseUint(name, 10, 32); err != nil {
			continue // not a pid directory
		}
		nsTarget, err := os.Readlink(filepath.Join(procRoot, name, "ns", "net"))
		if err != nil {
			continue // exited between listing and reading, or no permission
		}
		if _, ok := doneNS[nsTarget]; ok {
			continue // this namespace's tables were already read via another pid
		}
		if attempts[nsTarget] >= maxNSReadAttempts {
			continue // tried enough pids for this namespace; do not walk them all
		}
		attempts[nsTarget]++

		// udp and udp6 are read INDEPENDENTLY (finding №386): an unreadable or
		// absent udp table must not suppress udp6, nor the other way round.
		// Wave 6.3 item 2, finding №383: the line format /proc/net/udp6 uses is
		// identical to udp — a continuous hex address with no internal colons —
		// so connectedPort53Inodes parses it unchanged. udp6 missing entirely
		// (IPv6 disabled in the kernel) is normal, not an error.
		// net/udp decides whether this namespace counts as read: it exists for
		// every live process, so failing to open it means the pid went away (or
		// this agent may not read it), not that the namespace has nothing to
		// offer — another pid sharing the namespace can still serve it.
		udpOK := false
		if ns, err := connectedPort53Inodes(filepath.Join(procRoot, name, "net", "udp")); err == nil {
			udpOK = true
			for inode := range ns {
				inodes[inode] = struct{}{}
			}
		}
		// net/udp6 is purely additive and read INDEPENDENTLY (finding №386):
		// an unreadable udp must not suppress it, and its own absence — IPv6
		// disabled in the kernel — is normal rather than an error.
		if ns6, err := connectedPort53Inodes(filepath.Join(procRoot, name, "net", "udp6")); err == nil {
			for inode := range ns6 {
				inodes[inode] = struct{}{}
			}
		}
		if udpOK {
			doneNS[nsTarget] = struct{}{}
		}
	}
	return inodes, nil
}

// maxNSReadAttempts caps how many processes are tried per network namespace
// before giving up on it. A retry only happens when NEITHER udp nor udp6 could
// be read through the chosen pid — a pid that exited mid-scan, or one this
// agent may not read — and three tries is enough to survive that race while
// keeping a namespace this agent structurally cannot read (no CAP_SYS_PTRACE,
// not root) from costing one open() per process on the node.
const maxNSReadAttempts = 3

// connectedPort53Inodes parses /proc/net/udp or /proc/net/udp6 and returns
// the socket inodes of entries connected to remote port 53. "Connected"
// means the kernel recorded a specific non-zero remote address — exactly
// what connect() to a resolver address produces, and a merely
// bound-but-unconnected socket does not. Both files share the same column
// layout, including the address encoding (continuous hex, no colons within
// the address itself), so one parser covers both.
func connectedPort53Inodes(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	inodes := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			// Header: "sl local_address rem_address st tx_queue:rx_queue
			// tr:tm->when retrnsmt uid timeout inode ref pointer drops"
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		remAddrPort := strings.SplitN(fields[2], ":", 2)
		if len(remAddrPort) != 2 {
			continue
		}
		remAddr, remPort := remAddrPort[0], remAddrPort[1]
		if !strings.EqualFold(remPort, "0035") { // 53 in hex
			continue
		}
		if strings.Trim(remAddr, "0") == "" {
			continue // 0.0.0.0 — bound, not connected
		}
		inode := fields[9]
		if inode == "" || inode == "0" {
			continue
		}
		inodes[inode] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return inodes, nil
}

// seedSocketMapFromProcFDs walks every process's <procRoot>/<pid>/fd
// directory looking for sockets whose inode is in inodes, and inserts a
// (tgid, fd) -> 1 entry into m for each match. procRoot is "/proc" in
// production and a fabricated directory in tests, so the scan can be
// exercised deterministically without a real kernel. Best-effort: a
// process that exits mid-scan, or one this agent cannot read (permission),
// is skipped rather than failing the whole scan — the same tolerance
// trace_connect implicitly has (it only ever sees what it is attached in
// time to see).
func seedSocketMapFromProcFDs(m dnsSocketMapUpdater, procRoot string, inodes map[string]struct{}) (int, error) {
	procDir, err := os.Open(procRoot)
	if err != nil {
		return 0, err
	}
	defer procDir.Close()

	names, err := procDir.Readdirnames(-1)
	if err != nil {
		return 0, err
	}

	added := 0
	val := uint8(1)
	for _, name := range names {
		pid, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			continue // not a pid directory
		}
		fdDir := filepath.Join(procRoot, name, "fd")
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // exited between listing and reading, or no permission
		}
		for _, entry := range entries {
			fd, err := strconv.ParseUint(entry.Name(), 10, 32)
			if err != nil {
				continue
			}
			target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := target[len("socket:[") : len(target)-1]
			if _, ok := inodes[inode]; !ok {
				continue
			}
			key := dnsSocketKey{Tgid: uint32(pid), Fd: uint32(fd)}
			if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
				slog.Warn("dns: dns_socket_map backfill: failed to seed one entry",
					slog.Uint64("pid", pid), slog.Uint64("fd", fd), slog.Any("error", err))
				continue
			}
			added++
		}
	}
	return added, nil
}
