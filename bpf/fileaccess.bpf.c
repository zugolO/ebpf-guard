/*
 * fileaccess.bpf.c - eBPF program for file access monitoring.
 * Traces open, read, and write operations on files.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/*
 * Tracepoint for sys_enter_openat - captures file open operations.
 * openat is the modern syscall used by glibc for open().
 */
SEC("tp/syscalls/sys_enter_openat")
int BPF_PROG(trace_openat_enter, int dfd, const char *filename, int flags, umode_t mode)
{
	struct event *e;
	
	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;
	
	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	
	/* Fill file-specific data */
	e->file.op = FILE_OP_OPEN;
	e->file.flags = flags;
	e->file.mode = mode;
	
	/* Copy filename (may be truncated if path is long) */
	bpf_probe_read_user_str(&e->file.filename, sizeof(e->file.filename), filename);
	
	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_enter_openat2 - captures file open operations (newer syscall).
 * openat2 provides more flags control, used by newer glibc versions.
 */
SEC("tp/syscalls/sys_enter_openat2")
int BPF_PROG(trace_openat2_enter, int dfd, const char *filename, struct open_how *how, size_t size)
{
	struct event *e;
	
	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;
	
	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	
	/* Fill file-specific data */
	e->file.op = FILE_OP_OPEN;
	
	/* Read flags from open_how structure */
	__u64 flags = BPF_CORE_READ(how, flags);
	e->file.flags = (__s32)flags;
	e->file.mode = BPF_CORE_READ(how, mode);
	
	/* Copy filename */
	bpf_probe_read_user_str(&e->file.filename, sizeof(e->file.filename), filename);
	
	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_enter_read - captures file read operations.
 */
SEC("tp/syscalls/sys_enter_read")
int BPF_PROG(trace_read_enter, unsigned int fd, char *buf, size_t count)
{
	struct event *e;
	
	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;
	
	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	
	/* Fill file-specific data */
	e->file.op = FILE_OP_READ;
	e->file.flags = 0;
	e->file.mode = 0;
	
	/* We don't have the filename at this point, fd would need resolution */
	__builtin_memset(&e->file.filename, 0, sizeof(e->file.filename));
	
	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_enter_write - captures file write operations.
 */
SEC("tp/syscalls/sys_enter_write")
int BPF_PROG(trace_write_enter, unsigned int fd, const char *buf, size_t count)
{
	struct event *e;
	
	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;
	
	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	
	/* Fill file-specific data */
	e->file.op = FILE_OP_WRITE;
	e->file.flags = 0;
	e->file.mode = 0;
	
	/* We don't have the filename at this point, fd would need resolution */
	__builtin_memset(&e->file.filename, 0, sizeof(e->file.filename));
	
	submit_event(e);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
