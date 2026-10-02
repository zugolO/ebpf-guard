package correlator

// MuteFamilyCost is the ANSWER to "why is this family of rules still mute, and
// what would it cost to unmute it" — printed next to the family in the agent's
// own startup registry, so the reason and the price live in the agent's output
// instead of in prose (задача Т волны 7).
//
// Every number here was MEASURED and names its source; a price assigned by
// reasoning ("expensive") is exactly what the task forbids. A zero is a moment,
// not a property: the probe windows are 300 s on an idle node.
type MuteFamilyCost struct {
	// Reason is why no producer exists, in one sentence.
	Reason string
	// Price is what the producer that would unmute the family costs: events AND
	// alerts, because the second is what rejected socket(41), symlink(88) and,
	// on 01.10.2026, unlink(87) and rename(82).
	Price string
	// Source is the measurement the numbers come from.
	Source string
}

// Family keys.
const (
	MuteFamilyFileOp    = "file_op"
	MuteFamilyProto     = "proto"
	MuteFamilyEventType = "event_type"
)

var muteFamilyCosts = map[string]MuteFamilyCost{
	MuteFamilyFileOp: {
		Reason: "bpf/fileaccess.bpf.c hooks openat, chmod/fchmodat/fchmod, read and write only (dup* just keep the fd-to-path map): no hook produces file.op unlink, rmdir, truncate or rename",
		Price: "events: the eight candidate syscalls (unlink 87, unlinkat 263, rmdir 84, truncate 76, ftruncate 77, rename 82, renameat 264, renameat2 316) are 42 calls/min on an idle node, 34 of them ftruncate by systemd-journal; pairs of portions 2-4 realised 2.4-6x the probe, so about 100-250 events/min. " +
			"alerts are the real price: systemd-journal truncates journal files, the persistent journal is under /var/log/journal (3.2G), so ransomware_log_wipe (uid 0, no comm predicate) and evasion_log_clear (comm list says journald, the comm is systemd-journal) would alert about 33/min on the node's own journald unless an exe_path identity exclusion lands first. The path of those ftruncate calls was NOT measured (bpftrace counted by comm). Code: about 300 lines over bpf/common.h, bpf/fileaccess.bpf.c, the generated stubs, collector/fileaccess.go, pkg/types, metrics, plus a verifier run on the stand",
		Source: "server-logs/w7-syscall-price-c1-2026-10-01 (300 s, idle) and server-logs/collect-6.4-w669P2A..P4B",
	},
	MuteFamilyProto: {
		Reason: "bpf/network.bpf.c is a tcp_connect kprobe and emits IPPROTO_TCP (6) only: no hook produces proto 1 (ICMP), 47 (GRE), 255 or the other raw protocols",
		Price: "events: nearly free on an idle node, 300 s: icmp_rcv 1 call (0.2/min), __icmp_send 0, raw_sendmsg 0, ping_v4_sendmsg 0, gre_rcv unavailable (symbol absent, module not loaded); ESP/AH/IPv6 hooks not measured. " +
			"alerts and rules are the real price: netintr_icmp_outbound_large has no size predicate and would fire on every ICMP packet, and c2_icmp_large_payload reads payload size from dport, a field ICMP does not have, so the producer must define it",
		Source: "server-logs/w7-family-price-2026-10-02 (300 s, idle)",
	},
	MuteFamilyEventType: {
		Reason: "bpf/cgroup.bpf.c attaches to lsm/cgroup_attach_task, a hook no released kernel defines; the replacement producer is a different hook, not a newer kernel (finding 494)",
		Price: "events: tracepoint cgroup:cgroup_attach_task 0 calls and cgroup_transfer_tasks 0 in 300 s on an idle node (a moment, not a property: a container start migrates processes). " +
			"alerts: container_escape_cgroup_migrate matches ANY migration with new_cgroup_id != 0, so the alert price would be one per container or unit start unless the initial-cgroup comparison the LSM version intended is rebuilt in userspace",
		Source: "server-logs/w7-family-price-2026-10-02 (300 s, idle)",
	},
}

// MuteFamilyCostFor returns the recorded reason and price of a mute family.
func MuteFamilyCostFor(family string) (MuteFamilyCost, bool) {
	c, ok := muteFamilyCosts[family]
	return c, ok
}
