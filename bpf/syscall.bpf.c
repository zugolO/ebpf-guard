/*
 * syscall.bpf.c - eBPF program for syscall tracing via raw tracepoints.
 * Attaches to sys_enter, sys_exit, and sched_process_exec tracepoints.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* Raw tracepoint argument structure for sys_enter */
struct sys_enter_args {
	unsigned long long unused;
	long syscall_nr;
	unsigned long args[6];
};

/* Raw tracepoint argument structure for sys_exit */
struct sys_exit_args {
	unsigned long long unused;
	long syscall_nr;
	long ret;
};

/* Map to store syscall entry args for matching with exit */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct sys_enter_args);
} syscall_args SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx)
{
	struct event *e;
	__u64 pid_tgid;

	/* BPF-side content filtering: drop before touching the ring buffer */
	if (kernel_filter_enabled()) {
		if (comm_is_denied())
			return 0;
		if (!syscall_is_monitored(ctx->syscall_nr))
			return 0;
	}

	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_SYSCALL, 0);
	if (!e)
		return 0;

	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_SYSCALL;

	/* Fill syscall-specific data */
	e->syscall.nr = ctx->syscall_nr;
	e->syscall.ret = 0; /* Will be filled on exit */

	/* Copy syscall arguments */
	bpf_probe_read_kernel(&e->syscall.args, sizeof(e->syscall.args), &ctx->args);

	/* Store args for exit matching; track map-full events for observability */
	pid_tgid = bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&syscall_args, &pid_tgid, ctx, BPF_NOEXIST) == -E2BIG)
		record_map_full(MAP_FULL_IDX_SYSCALL_ARGS);

	submit_event(e);
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_args *ctx)
{
	struct event *e;
	struct sys_enter_args *entry_args;
	__u64 pid_tgid;

	/* BPF-side content filtering: drop before touching the ring buffer */
	if (kernel_filter_enabled()) {
		if (comm_is_denied())
			return 0;
		if (!syscall_is_monitored(ctx->syscall_nr))
			return 0;
	}

	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_SYSCALL, 0);
	if (!e)
		return 0;

	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_SYSCALL;

	/* Fill syscall-specific data */
	e->syscall.nr = ctx->syscall_nr;
	e->syscall.ret = ctx->ret;

	/* Try to get stored entry args */
	pid_tgid = bpf_get_current_pid_tgid();
	entry_args = bpf_map_lookup_elem(&syscall_args, &pid_tgid);
	if (entry_args) {
		bpf_probe_read_kernel(&e->syscall.args, sizeof(e->syscall.args),
			&entry_args->args);
		bpf_map_delete_elem(&syscall_args, &pid_tgid);
	} else {
		__builtin_memset(&e->syscall.args, 0, sizeof(e->syscall.args));
	}

	submit_event(e);
	return 0;
}

/*
 * trace_sched_process_exec - populate proc_args_map on every exec.
 *
 * Reads argv from task_struct->mm->arg_start..arg_end (BTF CO-RE) and stores
 * a NUL-terminated, space-joined copy in proc_args_map keyed by TGID.
 * Requires kernel 5.15+ with BTF support; falls back to /proc/PID/cmdline
 * in userspace when this program fails to load (see collector/syscall.go).
 */
SEC("tp/sched/sched_process_exec")
int trace_sched_process_exec(void *ctx)
{
	struct proc_args pa = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long arg_start, arg_end;
	long args_len, read_len;

	task = (struct task_struct *)bpf_get_current_task();
	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	arg_start = BPF_CORE_READ(mm, arg_start);
	arg_end   = BPF_CORE_READ(mm, arg_end);
	args_len  = (long)(arg_end - arg_start);
	if (args_len <= 0)
		return 0;

	if (args_len >= PROC_ARGS_MAX) {
		read_len = PROC_ARGS_MAX - 1;
		pa.truncated = 1;
	} else {
		read_len = args_len;
	}
	/* Bounds check lets the verifier prove read_len is in [1, PROC_ARGS_MAX-1]. */
	if (read_len <= 0 || read_len >= PROC_ARGS_MAX)
		return 0;

	if (bpf_probe_read_user(pa.args, (size_t)read_len, (void *)arg_start) < 0)
		return 0;

	/*
	 * Replace NUL argument separators with spaces so the result is a single
	 * printable string suitable for regex/contains rule matching.
	 * Bounded loop (PROC_ARGS_MAX - 1 = 511 iterations): safe for the verifier.
	 */
	for (int i = 0; i < PROC_ARGS_MAX - 1; i++) {
		if (pa.args[i] == '\0' && i < read_len - 1)
			pa.args[i] = ' ';
	}
	/* Ensure NUL termination at the real end. */
	if (read_len > 0 && read_len < PROC_ARGS_MAX)
		pa.args[read_len] = '\0';

	bpf_map_update_elem(&proc_args_map, &tgid, &pa, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
