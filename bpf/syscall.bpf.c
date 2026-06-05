/*
 * syscall.bpf.c - eBPF program for syscall tracing via raw tracepoints.
 * Attaches to sys_enter and sys_exit tracepoints.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
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

	/* Store args for exit matching */
	pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&syscall_args, &pid_tgid, ctx, BPF_ANY);

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

char LICENSE[] SEC("license") = "GPL";
