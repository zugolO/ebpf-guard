/*
 * fileaccess.bpf.c - eBPF program for file access monitoring with fd→path enrichment.
 *
 * fd→path enrichment design:
 *   1. sys_enter_openat / sys_enter_openat2 → store filename in fd_scratch_map keyed by pid_tgid
 *   2. sys_exit_openat / sys_exit_openat2  → move scratch entry to fd_path_map[(tgid<<32|fd)]
 *   3. sys_enter_close                     → delete fd_path_map entry
 *   4. sys_enter_read / sys_enter_write    → look up fd_path_map, embed resolved path in event
 *
 * Memory: LRU fd_path_map at 65536 entries × (8B key + 257B value) ≈ 17 MB.
 *         Scratch map sized to max in-flight opens (4096 entries).
 */

/* linux/ headers are superseded by vmlinux.h (included via common.h)
 * when doing CO-RE compilation. Do not re-add them here. */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Value stored in both scratch and fd→path maps. */
struct fd_path {
	char path[FILENAME_LEN];
	__u8 truncated; /* 1 if path was longer than FILENAME_LEN-1 bytes */
};

/*
 * fd_scratch_map — temporary per-thread storage for the filename between
 * sys_enter_openat and sys_exit_openat.
 * key: pid_tgid (__u64 from bpf_get_current_pid_tgid())
 * value: struct fd_path
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct fd_path);
} fd_scratch_map SEC(".maps");

/*
 * fd_path_map — durable fd→path table for the lifetime of an open fd.
 * key: (tgid << 32) | fd
 * value: struct fd_path
 * LRU eviction prevents map-full errors under high fd churn.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct fd_path);
} fd_path_map SEC(".maps");

/* Store filename into scratch map for the current thread. */
static __always_inline void scratch_store(const char *user_filename)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct fd_path scratch = {};
	long ret;

	ret = bpf_probe_read_user_str(scratch.path, sizeof(scratch.path), user_filename);
	scratch.truncated = (ret == (long)sizeof(scratch.path)) ? 1 : 0;
	bpf_map_update_elem(&fd_scratch_map, &pid_tgid, &scratch, BPF_ANY);
}

/* Move scratch entry to fd_path_map for the given fd, then delete scratch. */
static __always_inline void fd_commit(__u32 tgid, __s64 fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct fd_path *scratch;

	if (fd < 0)
		goto cleanup;

	scratch = bpf_map_lookup_elem(&fd_scratch_map, &pid_tgid);
	if (!scratch)
		goto cleanup;

	__u64 map_key = ((__u64)tgid << 32) | (__u64)(unsigned int)fd;
	bpf_map_update_elem(&fd_path_map, &map_key, scratch, BPF_ANY);

cleanup:
	bpf_map_delete_elem(&fd_scratch_map, &pid_tgid);
}

/* Look up fd→path and copy into event filename field. */
static __always_inline void enrich_from_fd(struct event *e, __u32 tgid, __u32 fd)
{
	__u64 map_key = ((__u64)tgid << 32) | (__u64)fd;
	struct fd_path *fdp;

	fdp = bpf_map_lookup_elem(&fd_path_map, &map_key);
	if (!fdp)
		return;

	__builtin_memcpy(e->file.filename, fdp->path, FILENAME_LEN);
	e->file.fd_path_truncated = fdp->truncated;
}

/*
 * Tracepoint for sys_enter_openat — capture filename into scratch map.
 */
SEC("tp/syscalls/sys_enter_openat")
int BPF_PROG(trace_open, int dfd, const char *filename, int flags, umode_t mode)
{
	struct event *e;

	scratch_store(filename);

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_OPEN;
	e->file.flags = flags;
	e->file.mode = mode;
	bpf_probe_read_user_str(&e->file.filename, sizeof(e->file.filename), filename);
	e->file.fd_path_truncated = 0;

	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_exit_openat — commit scratch→fd_path_map using the returned fd.
 * Uses raw context (struct trace_event_raw_sys_exit) to avoid BPF_PROG context
 * access rejection that occurs with single-argument sys_exit typed tracepoints.
 */
SEC("tp/syscalls/sys_exit_openat")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	fd_commit(tgid, ctx->ret);
	return 0;
}

/*
 * Tracepoint for sys_enter_openat2 — capture filename into scratch map.
 */
SEC("tp/syscalls/sys_enter_openat2")
int BPF_PROG(trace_openat2_enter, int dfd, const char *filename, struct open_how *how, size_t size)
{
	struct event *e;

	scratch_store(filename);

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_OPEN;

	__u64 flags = BPF_CORE_READ(how, flags);
	e->file.flags = (__s32)flags;
	e->file.mode = BPF_CORE_READ(how, mode);
	bpf_probe_read_user_str(&e->file.filename, sizeof(e->file.filename), filename);
	e->file.fd_path_truncated = 0;

	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_exit_openat2 — commit scratch→fd_path_map.
 * Uses raw context struct for the same reason as trace_open_exit.
 */
SEC("tp/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	fd_commit(tgid, ctx->ret);
	return 0;
}

/*
 * Tracepoint for sys_enter_close — evict fd_path_map entry on close(2).
 * Uses raw context (struct trace_event_raw_sys_enter) instead of BPF_PROG
 * to avoid "invalid bpf_context access off=0 size=8" verifier rejection
 * that occurs when BPF_PROG tries to extract a single unsigned int arg.
 */
SEC("tp/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	unsigned int fd = (unsigned int)ctx->args[0];
	__u64 map_key = ((__u64)tgid << 32) | (__u64)fd;

	bpf_map_delete_elem(&fd_path_map, &map_key);
	return 0;
}

/*
 * Tracepoint for sys_enter_read — emit event with fd-resolved filename.
 */
SEC("tp/syscalls/sys_enter_read")
int BPF_PROG(trace_read, unsigned int fd, char *buf, size_t count)
{
	struct event *e;
	__u64 pid_tgid;
	__u32 tgid;

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_READ;
	e->file.flags = 0;
	e->file.mode = 0;
	__builtin_memset(&e->file.filename, 0, sizeof(e->file.filename));
	e->file.fd_path_truncated = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (__u32)(pid_tgid >> 32);
	enrich_from_fd(e, tgid, fd);

	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_enter_write — emit event with fd-resolved filename.
 */
SEC("tp/syscalls/sys_enter_write")
int BPF_PROG(trace_write, unsigned int fd, const char *buf, size_t count)
{
	struct event *e;
	__u64 pid_tgid;
	__u32 tgid;

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_WRITE;
	e->file.flags = 0;
	e->file.mode = 0;
	__builtin_memset(&e->file.filename, 0, sizeof(e->file.filename));
	e->file.fd_path_truncated = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (__u32)(pid_tgid >> 32);
	enrich_from_fd(e, tgid, fd);

	submit_event(e);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
