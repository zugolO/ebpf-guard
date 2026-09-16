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
// new here. IPv4 only, matching is_dns_packet's current AF_INET-only
// scope — /proc/<pid>/net/udp6 is a separately tracked blind spot
// (6.3.7), not silently extended by this scan.
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
// from procRoot, reading each namespace's udp table exactly once
// regardless of how many processes share it. Socket inodes are allocated
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

	seenNS := make(map[string]struct{})
	inodes := make(map[string]struct{})
	for _, name := range names {
		if _, err := strconv.ParseUint(name, 10, 32); err != nil {
			continue // not a pid directory
		}
		nsTarget, err := os.Readlink(filepath.Join(procRoot, name, "ns", "net"))
		if err != nil {
			continue // exited between listing and reading, or no permission
		}
		if _, ok := seenNS[nsTarget]; ok {
			continue // this namespace's udp table was already read via another pid
		}
		seenNS[nsTarget] = struct{}{}

		ns, err := connectedPort53Inodes(filepath.Join(procRoot, name, "net", "udp"))
		if err != nil {
			continue // net/udp unreadable for this pid (exited, permission) — best-effort
		}
		for inode := range ns {
			inodes[inode] = struct{}{}
		}
	}
	return inodes, nil
}

// connectedPort53Inodes parses /proc/net/udp and returns the socket inodes
// of entries connected to remote port 53. "Connected" means the kernel
// recorded a specific non-zero remote address — exactly what connect() to
// a resolver address produces, and a merely bound-but-unconnected socket
// does not.
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
