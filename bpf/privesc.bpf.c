/*
 * privesc.bpf.c - Privilege escalation detection via capability tracking.
 *
 * Attaches to:
 *   - tracepoint sys_enter_capset  — userspace capability requests
 *   - kprobe commit_creds          — kernel credential commits (covers setuid,
 *                                    execve with SUID bit, and other paths)
 *
 * Emits EVENT_TYPE_PRIVESC when the effective capability set changes.
 * old_caps / new_caps are stored as uint64 bitmasks (Linux eff cap word 0).
 */

/* linux/ headers are superseded by vmlinux.h (included via common.h)
 * when doing CO-RE compilation. Do not re-add them here. */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Per-process map: stores the last-seen effective caps so we can compute delta. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);   /* pid */
	__type(value, __u64); /* last effective caps bitmask */
} pid_caps SEC(".maps");

/*
 * privesc_event extends the common event union with caps data.
 * We use the syscall union slot (largest slot in common.h) to carry
 * old_caps / new_caps without changing the wire format:
 *   args[0] = old_caps
 *   args[1] = new_caps
 * This avoids modifying common.h's packed struct layout.
 */

/* Helper: emit a privesc event with old/new caps in the syscall.args slots. */
static __always_inline void emit_privesc(__u32 pid, __u64 old_caps, __u64 new_caps)
{
	struct event *e;

	/* Only emit when caps actually changed. */
	if (old_caps == new_caps)
		return;

	e = reserve_event();
	if (!e)
		return;

	fill_process_info(e);
	e->type = EVENT_TYPE_PRIVESC;

	/* Encode caps in the syscall union (args[0]=old, args[1]=new). */
	e->syscall.nr    = 0;
	e->syscall.ret   = 0;
	e->syscall.args[0] = old_caps;
	e->syscall.args[1] = new_caps;

	/* Update stored caps for this PID. */
	bpf_map_update_elem(&pid_caps, &pid, &new_caps, BPF_ANY);

	submit_event(e);
}

/*
 * tracepoint/syscalls/sys_enter_capset
 * Fires when a process calls capset(2) to change its own capabilities.
 * ctx->args[1] is a pointer to struct __user_cap_data_struct.
 * We read the effective word from the header.
 */
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32);
	__u64 *stored;
	__u64 old_caps = 0;

	stored = bpf_map_lookup_elem(&pid_caps, &pid);
	if (stored)
		old_caps = *stored;

	/*
	 * We cannot safely read the userspace cap_data pointer here because
	 * the syscall hasn't executed yet. We store the old caps now and let
	 * commit_creds pick up the new value after the kernel applies them.
	 * The tracepoint entry ensures we capture the baseline for new PIDs.
	 */
	if (!stored)
		bpf_map_update_elem(&pid_caps, &pid, &old_caps, BPF_NOEXIST);

	return 0;
}

/*
 * kprobe/commit_creds
 * Called by the kernel whenever a new credential set is committed to a task.
 * This covers setuid, execve with SUID, capset, and other paths.
 * Argument: struct cred *new  (the new credentials to commit)
 */
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new_cred)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32);
	__u64 *stored;
	__u64 old_caps = 0;
	__u64 new_caps = 0;
	kernel_cap_t eff;

	/* Read new effective capability set (word 0 covers caps 0–63). */
	BPF_CORE_READ_INTO(&eff, new_cred, cap_effective);
#if defined(__KERNEL_CAP_T_DEFINED) || 1
	/* kernel_cap_t has a __u32 cap[] array on 64-bit kernels.
	 * cap_effective.cap[0] holds bits 0-31, cap[1] holds 32-63. */
	new_caps = ((__u64)BPF_CORE_READ(new_cred, cap_effective.cap[1]) << 32) |
	            (__u64)BPF_CORE_READ(new_cred, cap_effective.cap[0]);
#endif

	stored = bpf_map_lookup_elem(&pid_caps, &pid);
	if (stored)
		old_caps = *stored;

	emit_privesc(pid, old_caps, new_caps);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
