/* lsm.bpf.c — eBPF LSM hooks for pre-execution enforcement and detection
 *
 * Hooks implemented:
 *   Sprint 22.0: bpf_file_open, bpf_socket_connect, bpf_task_kill
 *   Sprint 33.0: kernel_module_request, kernel_read_file (kmod load detection)
 *
 * Requires kernel 5.7+ with CONFIG_BPF_LSM=y.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

/* LSM blocklist map: PID -> blocked path hash set indicator
 * LRU eviction ensures bounded memory usage
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   /* PID */
	__type(value, __u8);  /* 1 = blocked */
} lsm_blocklist SEC(".maps");

/* Agent whitelist: PIDs that should never be blocked (the agent itself) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);   /* PID */
	__type(value, __u8);  /* 1 = whitelisted */
} lsm_agent_whitelist SEC(".maps");

/* LSM action stats: hook type -> count */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);   /* stat index */
	__type(value, __u64); /* count */
} lsm_stats SEC(".maps");

/* Stat indices */
#define LSM_STAT_FILE_OPEN_ALLOW  0
#define LSM_STAT_FILE_OPEN_BLOCK  1
#define LSM_STAT_SOCK_CONN_ALLOW  2
#define LSM_STAT_SOCK_CONN_BLOCK  3
#define LSM_STAT_TASK_KILL_ALLOW  4
#define LSM_STAT_TASK_KILL_BLOCK  5
#define LSM_STAT_KMOD_LOAD        6
#define LSM_STAT_CGROUP_ESC       7

/* Ring buffer for kmod / cgroup-escape events (separate from syscall ring buffer
 * in common.h to avoid contention on the hot syscall path). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024); /* 64KB is sufficient for infrequent events */
} lsm_events SEC(".maps");

/* Per-PID initial cgroup ID recorded at exec time.
 * Used by the cgroup_attach_task hook to detect namespace migration.
 * Key: PID (u32), Value: cgroup_id (u64).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} pid_initial_cgroup SEC(".maps");

/* Helper to check if PID is the agent itself */
static __always_inline bool is_agent_pid(__u32 pid)
{
	__u8 *val = bpf_map_lookup_elem(&lsm_agent_whitelist, &pid);
	return val != NULL && *val == 1;
}

/* Helper to check if PID is in blocklist */
static __always_inline bool is_blocked_pid(__u32 pid)
{
	__u8 *val = bpf_map_lookup_elem(&lsm_blocklist, &pid);
	return val != NULL && *val == 1;
}

/* Helper to update stats */
static __always_inline void update_stat(__u32 stat_idx)
{
	__u64 *count = bpf_map_lookup_elem(&lsm_stats, &stat_idx);
	if (count) {
		__sync_fetch_and_add(count, 1);
	}
}

/* LSM hook: file_open — called before opening a file
 * 
 * Return 0 to allow, -EPERM to block
 * 
 * Performance note: Fast path (non-blocked PID) is a single map lookup
 * and should complete in < 100ns.
 */
SEC("lsm/bpf_file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Fast path 1: Agent itself is always allowed */
	if (is_agent_pid(pid)) {
		update_stat(LSM_STAT_FILE_OPEN_ALLOW);
		return 0;
	}

	/* Fast path 2: PID not in blocklist */
	if (!is_blocked_pid(pid)) {
		update_stat(LSM_STAT_FILE_OPEN_ALLOW);
		return 0;
	}

	/* Slow path: PID is blocked — would check path here
	 * For now, block all file access for blocked PIDs
	 * TODO: Add per-path blocklist in future sprint
	 */
	update_stat(LSM_STAT_FILE_OPEN_BLOCK);
	return -EPERM;
}

/* LSM hook: socket_connect — called before TCP connect
 *
 * Return 0 to allow, -EPERM to block
 */
SEC("lsm/bpf_socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *addr, int addrlen)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Fast path 1: Agent itself is always allowed */
	if (is_agent_pid(pid)) {
		update_stat(LSM_STAT_SOCK_CONN_ALLOW);
		return 0;
	}

	/* Fast path 2: PID not in blocklist */
	if (!is_blocked_pid(pid)) {
		update_stat(LSM_STAT_SOCK_CONN_ALLOW);
		return 0;
	}

	/* Slow path: PID is blocked */
	update_stat(LSM_STAT_SOCK_CONN_BLOCK);
	return -EPERM;
}

/* LSM hook: task_kill — called before sending signal
 *
 * Return 0 to allow, -EPERM to block
 * This hook is audit-only by default (always allows)
 */
SEC("lsm/bpf_task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *target, struct kernel_siginfo *info,
	     int sig, const struct cred *cred)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Always allow but audit the action */
	update_stat(LSM_STAT_TASK_KILL_ALLOW);

	/* TODO: Add audit logging via perf event ring buffer
	 * struct lsm_audit_event {
	 *     __u32 pid;
	 *     __u32 target_pid;
	 *     int sig;
	 *     __u8 action;  // 0=audit, 1=block
	 * };
	 */

	return 0;
}

/* -------------------------------------------------------------------------
 * Sprint 33.0: Kernel Module Load Detection
 * -------------------------------------------------------------------------
 *
 * LSM hook: kernel_module_request
 * Called when the kernel requests automatic module loading (e.g., modprobe).
 * We emit an event and always return 0 (audit-only; policy enforced in Go).
 */
SEC("lsm/kernel_module_request")
int BPF_PROG(lsm_kernel_module_request, char *kmod_name)
{
	struct kmod_event *e;

	update_stat(LSM_STAT_KMOD_LOAD);

	e = bpf_ringbuf_reserve(&lsm_events, sizeof(struct kmod_event), 0);
	if (!e)
		return 0;

	e->type      = EVENT_TYPE_KMOD_LOAD;
	e->timestamp = bpf_ktime_get_ns();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)(pid_tgid >> 32);
	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = (__u32)uid_gid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Fill parent info */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = task->real_parent;
	if (parent) {
		e->ppid = parent->tgid;
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm), &parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}

	/* Copy module name (kernel-provided pointer) */
	if (kmod_name)
		bpf_probe_read_kernel_str(&e->mod_name, sizeof(e->mod_name), kmod_name);
	else
		__builtin_memset(&e->mod_name, 0, sizeof(e->mod_name));

	e->from_tmpfs = 0; /* not path-based; kernel_read_file hook handles path check */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * LSM hook: kernel_read_file
 * Called when the kernel reads a file for interpretation (modules, firmware, etc.).
 * We emit an event only when id == READING_MODULE.
 *
 * kernel_read_file_id enum: READING_UNKNOWN=0, READING_FIRMWARE=1,
 * READING_MODULE=2, READING_KEXEC_IMAGE=3, READING_KEXEC_INITRAMFS=4,
 * READING_POLICY=5, READING_X509_CERTIFICATE=6.
 */
#define READING_MODULE 2

SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	if (id != READING_MODULE)
		return 0;

	update_stat(LSM_STAT_KMOD_LOAD);

	struct kmod_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(struct kmod_event), 0);
	if (!e)
		return 0;

	e->type      = EVENT_TYPE_KMOD_LOAD;
	e->timestamp = bpf_ktime_get_ns();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)(pid_tgid >> 32);
	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = (__u32)uid_gid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = task->real_parent;
	if (parent) {
		e->ppid = parent->tgid;
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm), &parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}

	/* Read file path into mod_name via dentry */
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if (dentry)
		bpf_probe_read_kernel_str(&e->mod_name, sizeof(e->mod_name),
					  BPF_CORE_READ(dentry, d_name.name));
	else
		__builtin_memset(&e->mod_name, 0, sizeof(e->mod_name));

	/* Check if path starts with /tmp or /dev/shm (suspicious load location) */
	e->from_tmpfs = 0;
	if (e->mod_name[0] == '/' &&
	    ((e->mod_name[1] == 't' && e->mod_name[2] == 'm' && e->mod_name[3] == 'p') ||
	     (e->mod_name[1] == 'd' && e->mod_name[2] == 'e' && e->mod_name[3] == 'v')))
		e->from_tmpfs = 1;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* -------------------------------------------------------------------------
 * Sprint 33.0: exec-time cgroup recording (used by cgroup.bpf.c)
 * Record the initial cgroup ID of each process at exec time so that
 * cgroup_attach_task can detect migration out of the container's cgroup tree.
 * -------------------------------------------------------------------------
 */
SEC("tp/sched/sched_process_exec")
int trace_exec_record_cgroup(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	bpf_map_update_elem(&pid_initial_cgroup, &pid, &cgroup_id, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
