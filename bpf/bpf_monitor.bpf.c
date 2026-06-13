/*
 * bpf_monitor.bpf.c — bpf() syscall monitoring for ebpf-guard.
 *
 * Attaches kprobe/kretprobe to __x64_sys_bpf to detect malicious
 * BPF program loading. eBPF-based rootkits (TripleCross, ebpfkit,
 * boopkit) load their own BPF programs to hide traffic and processes.
 * This program captures BPF_PROG_LOAD and BPF_MAP_CREATE calls,
 * recording the caller identity, command, program type, and result.
 *
 * Target: Linux kernel 5.15+
 */
#include "common.h"
/* linux/bpf.h superseded by vmlinux.h included via common.h */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* BPF commands we specifically monitor */
#define BPF_MAP_CREATE 0
#define BPF_PROG_LOAD  5

/*
 * bpf_entry — stored between kprobe (enter) and kretprobe (exit).
 * Keyed by pid_tgid in a LRU hash map so stale entries are
 * automatically evicted under memory pressure.
 */
struct bpf_entry {
	__u32 cmd;
	__u32 prog_type; /* prog_type (PROG_LOAD) or map_type (MAP_CREATE) at attr offset 0 */
};

/* LRU hash: pid_tgid → bpf_entry, 4096 slots, auto-eviction */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);               /* pid_tgid */
	__type(value, struct bpf_entry);
} bpf_entry_map SEC(".maps");

/* Dedicated ring buffer for bpf monitor events — separate from the shared
 * events map so that the bpf_event struct can have its own layout
 * without conflicting with the union-based struct event in common.h. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} bpfmonitor_events SEC(".maps");

/*
 * bpf_event — wire format for bpf() syscall monitoring.
 * Must match BpfMonitorRawEvent in internal/bpf/syscall_bpf_gen.go.
 * Packed, little-endian layout:
 *
 *   [0 ] type         uint32   (4)
 *   [4 ] timestamp    uint64   (8)
 *   [12] pid          uint32   (4)
 *   [16] tgid         uint32   (4)
 *   [20] ppid         uint32   (4)
 *   [24] uid          uint32   (4)
 *   [28] comm         [16]byte (16)
 *   [44] parent_comm  [16]byte (16)
 *   [60] cmd          uint32   (4)
 *   [64] prog_type    uint32   (4)
 *   [68] ret          int32    (4)
 *
 * Total: 72 bytes
 */
struct bpf_event {
	__u32 type;
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u8  comm[16];
	__u8  parent_comm[16];
	__u32 cmd;
	__u32 prog_type;
	__s32 ret;
} __attribute__((packed));

/*
 * Helper: fill process identity fields (pid, tgid, ppid, uid, comm,
 * parent_comm, timestamp) into a bpf_event.  Mirrors the pattern in
 * common.h fill_process_info for the shared struct event.
 */
static __always_inline void fill_bpf_process_info(struct bpf_event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct task_struct *task;
	struct task_struct *parent;

	e->pid  = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->uid  = (__u32)uid_gid;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = bpf_ktime_get_ns();

	task   = (struct task_struct *)bpf_get_current_task();
	if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) == 0) {
		e->ppid = (__u32)BPF_CORE_READ(parent, tgid);
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm),
				      parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}
}

/*
 * kprobe on __x64_sys_bpf(int cmd, union bpf_attr __user *uattr, unsigned int size)
 *
 * Filters for BPF_PROG_LOAD and BPF_MAP_CREATE, reads prog_type/map_type
 * from the userspace attr at offset 0, and stores the entry in bpf_entry_map
 * for retrieval by the kretprobe handler.
 */
SEC("kprobe/__x64_sys_bpf")
int BPF_KPROBE(trace_bpf_enter, int cmd, void __user *uattr, unsigned int size)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct bpf_entry entry = {};
	__u32 type_field = 0;

	/* Only care about program loads and map creates */
	if (cmd != BPF_PROG_LOAD && cmd != BPF_MAP_CREATE)
		return 0;

	entry.cmd = (__u32)cmd;

	/*
	 * Read the first 4 bytes of the bpf_attr union from userspace.
	 * For BPF_PROG_LOAD this is ->prog_type; for BPF_MAP_CREATE
	 * this is ->map_type.  Both sit at offset 0 in their respective
	 * anonymous structs inside the bpf_attr union.
	 */
	if (uattr) {
		bpf_probe_read_user(&type_field, sizeof(type_field), uattr);
	}
	entry.prog_type = type_field;

	bpf_map_update_elem(&bpf_entry_map, &pid_tgid, &entry, BPF_ANY);

	return 0;
}

/*
 * kretprobe on __x64_sys_bpf — emits the event with the return value.
 *
 * Looks up the entry stored by the kprobe handler, builds the event,
 * submits it to the ring buffer, and cleans up the entry map.
 */
SEC("kretprobe/__x64_sys_bpf")
int BPF_KRETPROBE(trace_bpf_exit, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct bpf_entry *entry;
	struct bpf_event *evt;

	entry = bpf_map_lookup_elem(&bpf_entry_map, &pid_tgid);
	if (!entry)
		return 0;

	evt = bpf_ringbuf_reserve(&bpfmonitor_events, sizeof(*evt), 0);
	if (!evt) {
		bpf_map_delete_elem(&bpf_entry_map, &pid_tgid);
		return 0;
	}

	evt->type      = EVENT_TYPE_BPF_PROGRAM;
	evt->cmd       = entry->cmd;
	evt->prog_type = entry->prog_type;
	evt->ret       = (__s32)ret;

	fill_bpf_process_info(evt);

	bpf_ringbuf_submit(evt, 0);
	bpf_map_delete_elem(&bpf_entry_map, &pid_tgid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
