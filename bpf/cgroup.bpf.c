/* cgroup.bpf.c — Container cgroup escape detection via LSM hooks
 *
 * Detects processes that migrate out of their initial cgroup namespace
 * by comparing the cgroup ID at attach time with the ID recorded at exec.
 *
 * Requires kernel 5.7+ with CONFIG_BPF_LSM=y.
 * Part of Sprint 33.0: Container Cgroup Escape Detection.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

/* Ring buffer for cgroup escape events (shared with lsm_events in lsm.bpf.c).
 * Because each BPF object file has its own map instances, we declare a
 * separate ring buffer here. The Go KmodCollector reads from both.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} cgroup_events SEC(".maps");

/* Per-PID initial cgroup ID — written by trace_exec_record_cgroup in lsm.bpf.c.
 * We declare a matching map here so that cgroup_attach_task can look it up.
 * At load time both maps must be pinned to the same kernel map object
 * (achieved via bpf_map_update_elem with the same name in Go).
 *
 * For simplicity the Go loader shares a single BPF object that merges both
 * source files; this declaration is kept for readability.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} pid_initial_cgroup SEC(".maps");

/*
 * LSM hook: cgroup_attach_task
 * Called when a task is being attached to a new cgroup.
 *
 * Parameters:
 *   dst_cgrp  — the destination cgroup
 *   leader    — the task being moved
 *   threadgroup — whether the whole thread group is being moved
 *
 * We look up the PID's recorded initial cgroup ID. If the new cgroup ID
 * differs, we emit a cgroup_escape_event. We always return 0 (audit-only).
 */
SEC("lsm/cgroup_attach_task")
int BPF_PROG(lsm_cgroup_attach_task, struct cgroup *dst_cgrp,
	     struct task_struct *leader, bool threadgroup)
{
	__u32 pid = BPF_CORE_READ(leader, tgid);

	/* Look up the initial cgroup recorded at exec */
	__u64 *init_id = bpf_map_lookup_elem(&pid_initial_cgroup, &pid);
	if (!init_id)
		return 0; /* No record — exec hook didn't fire or PID recycled */

	/* Get the destination cgroup's ID */
	__u64 new_id = BPF_CORE_READ(dst_cgrp, kn, id);

	/* Allow movement within the same cgroup (no-op or same hierarchy) */
	if (new_id == *init_id)
		return 0;

	/* Emit a cgroup escape event */
	struct cgroup_escape_event *e =
		bpf_ringbuf_reserve(&cgroup_events, sizeof(struct cgroup_escape_event), 0);
	if (!e)
		return 0;

	e->type           = EVENT_TYPE_CGROUP_ESC;
	e->timestamp      = bpf_ktime_get_ns();
	e->pid            = pid;
	e->init_cgroup_id = *init_id;
	e->new_cgroup_id  = new_id;

	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = (__u32)uid_gid;

	/* Use leader's comm */
	bpf_probe_read_kernel(&e->comm, sizeof(e->comm),
			      BPF_CORE_READ(leader, comm));

	/* Parent info */
	struct task_struct *parent = BPF_CORE_READ(leader, real_parent);
	if (parent) {
		e->ppid = BPF_CORE_READ(parent, tgid);
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm),
				      BPF_CORE_READ(parent, comm));
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
