/*
 * iouring.bpf.c — io_uring activity monitoring for ebpf-guard.
 *
 * Attaches kprobes to io_uring_setup and io_uring_enter to detect
 * processes using the io_uring interface. io_uring bypasses traditional
 * syscall tracepoints, creating a blind spot for tracepoint-based
 * security agents. This program closes that gap by emitting events
 * whenever a process creates or submits work to an io_uring instance.
 *
 * Target: Linux kernel 5.15+
 */
#include "common.h"
/* linux/bpf.h superseded by vmlinux.h included via common.h */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Dedicated ring buffer for io_uring events — separate from the shared
 * events map so that the io_uring_event struct can have its own layout
 * without conflicting with the union-based struct event in common.h. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} iouring_events SEC(".maps");

/* io_uring event wire format — packed, little-endian.
 * Must match IOUringRawEvent in internal/bpf/syscall_bpf_gen.go. */
struct io_uring_event {
	__u32 type;            /* EVENT_TYPE_IO_URING = 14 */
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u8  comm[16];
	__u8  parent_comm[16];
	__u8  op;              /* 0 = io_uring_setup, 1 = io_uring_enter */
	__u32 flags;           /* setup: IORING_SETUP_* flags; enter: IORING_ENTER_* flags */
	__s32 fd;              /* io_uring instance fd (-1 for setup before return) */
	__u32 to_submit;       /* number of SQEs to submit (enter only) */
} __attribute__((packed));

/* io_uring_setup(entries, params) — kprobe on __x64_sys_io_uring_setup */
SEC("kprobe/__x64_sys_io_uring_setup")
int BPF_KPROBE(trace_io_uring_setup, unsigned int entries,
	       struct io_uring_params __user *params)
{
	struct io_uring_event *evt;
	__u32 flags = 0;

	evt = bpf_ringbuf_reserve(&iouring_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->type      = EVENT_TYPE_IO_URING;
	evt->timestamp = bpf_ktime_get_ns();
	evt->pid       = bpf_get_current_pid_tgid() >> 32;
	evt->tgid      = (__u32)bpf_get_current_pid_tgid();
	evt->uid       = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));

	/* ppid and parent_comm — best-effort from task_struct */
	{
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct task_struct *parent;
		if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) == 0) {
			evt->ppid = (__u32)BPF_CORE_READ(parent, tgid);
			bpf_probe_read_kernel(evt->parent_comm, sizeof(evt->parent_comm),
					      parent->comm);
		} else {
			evt->ppid = 0;
			__builtin_memset(evt->parent_comm, 0, sizeof(evt->parent_comm));
		}
	}

	/* Read flags from userspace io_uring_params (best-effort). */
	if (params) {
		bpf_probe_read_user(&flags, sizeof(flags), &params->flags);
	}

	evt->op        = 0;       /* io_uring_setup */
	evt->flags     = flags;
	evt->fd        = -1;
	evt->to_submit = entries;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz) — kprobe.
 * libbpf 0.5 BPF_KPROBE supports at most 5 typed args; read pt_regs directly.
 * On x86_64 __x64_sys_* wrappers, PARM1 is a pointer to the inner pt_regs
 * holding the actual syscall arguments: di=fd, si=to_submit, r10=flags. */
SEC("kprobe/__x64_sys_io_uring_enter")
int trace_io_uring_enter(struct pt_regs *ctx)
{
	struct pt_regs *inner = (struct pt_regs *)PT_REGS_PARM1(ctx);
	unsigned long fd_raw = 0, to_submit_raw = 0, flags_raw = 0;
	struct io_uring_event *evt;

	bpf_probe_read_kernel(&fd_raw,        sizeof(fd_raw),        &inner->di);
	bpf_probe_read_kernel(&to_submit_raw, sizeof(to_submit_raw), &inner->si);
	bpf_probe_read_kernel(&flags_raw,     sizeof(flags_raw),     &inner->r10);

	evt = bpf_ringbuf_reserve(&iouring_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->type      = EVENT_TYPE_IO_URING;
	evt->timestamp = bpf_ktime_get_ns();
	evt->pid       = bpf_get_current_pid_tgid() >> 32;
	evt->tgid      = (__u32)bpf_get_current_pid_tgid();
	evt->uid       = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));

	{
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct task_struct *parent;
		if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) == 0) {
			evt->ppid = (__u32)BPF_CORE_READ(parent, tgid);
			bpf_probe_read_kernel(evt->parent_comm, sizeof(evt->parent_comm),
					      parent->comm);
		} else {
			evt->ppid = 0;
			__builtin_memset(evt->parent_comm, 0, sizeof(evt->parent_comm));
		}
	}

	evt->op        = 1;
	evt->flags     = (__u32)flags_raw;
	evt->fd        = (__s32)(unsigned int)fd_raw;
	evt->to_submit = (__u32)to_submit_raw;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
