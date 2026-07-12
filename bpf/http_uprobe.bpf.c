/*
 * http_uprobe.bpf.c - eBPF uprobe programs for plaintext (non-TLS) HTTP inspection.
 *
 * Attaches uprobes to libc `read`/`recv` in known web-server processes to capture
 * request/response bytes for traffic that never goes through TLS (SSL_read/SSL_write
 * are already covered by tls_uprobe.bpf.c). Complements the TLS collector: together
 * they close the "we can only see HTTP payloads that go through OpenSSL" gap from
 * issue #281.
 *
 * Target: Linux kernel 5.15+ with BTF/CO-RE support.
 * Requires: CAP_SYS_PTRACE for uprobe attachment.
 *
 * Design notes:
 * - Hooking libc read()/recv() globally (every process, every call) would be far
 *   too expensive and noisy - virtually all processes call read(). Userspace
 *   (internal/collector) is responsible for only attaching these uprobes to
 *   processes whose comm matches a configured list of known web-server binaries
 *   (nginx, apache2/httpd, node, python*, php-fpm, java, ruby, gunicorn, uwsgi, ...).
 * - Even scoped to those processes, read()/recv() is called for far more than just
 *   HTTP request/response bytes (config files, sockets to other backends, etc).
 *   To keep volume bounded we apply an in-kernel filter: only submit an event if
 *   the captured buffer's first bytes look like an HTTP request line
 *   ("GET ", "POST ", ...) or a status line ("HTTP/"). Everything else is dropped
 *   in-kernel and never reaches the ring buffer.
 *
 * Limitations:
 * - Only observes traffic read via plain read()/recv() - won't see data read via
 *   readv/recvmsg/io_uring, or userspace TLS libraries other than libssl (already
 *   handled separately by tls_uprobe.bpf.c).
 * - First 256 bytes only (configurable via HTTP_DATA_MAX).
 * - May miss a request if the HTTP method line spans multiple read() calls (rare
 *   for typical socket buffering, but possible under fragmentation).
 */

#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Plaintext-HTTP-specific event type */
#define EVENT_TYPE_HTTP_PLAINTEXT 16

/* Direction codes - mirrors types.HTTPDirection in pkg/types/event.go */
#define HTTP_DIR_REQUEST  0 /* Inbound data (read/recv on a server socket) */
#define HTTP_DIR_RESPONSE 1 /* Outbound data (write/send on a server socket) */

/* Maximum HTTP data to capture per event */
#define HTTP_DATA_MAX 256

/*
 * Extended event structure for plaintext HTTP events.
 * Field layout intentionally mirrors struct tls_event in tls_uprobe.bpf.c so the
 * userspace decoder (internal/collector/http_uprobe.go) can reuse the same
 * conversion pattern as TLSEventRaw.ToTypesEvent().
 */
struct http_event {
	__u32 type;
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u8  comm[COMM_LEN];
	__u8  parent_comm[COMM_LEN];

	__u8  direction;         /* HTTP_DIR_REQUEST or HTTP_DIR_RESPONSE */
	__u32 data_len;          /* Actual data length (may be > HTTP_DATA_MAX) */
	__u32 captured_len;      /* Bytes actually captured (<= HTTP_DATA_MAX) */
	__u8  data[HTTP_DATA_MAX]; /* Captured plaintext data */
} __attribute__((packed));

/* Ring buffer for plaintext HTTP events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); /* 4MB ring buffer */
} http_events SEC(".maps");

/*
 * Helper: Fill process info for HTTP events.
 * Duplicated from common.h to work with http_event struct (same pattern as
 * fill_tls_process_info in tls_uprobe.bpf.c).
 */
static __always_inline void fill_http_process_info(struct http_event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct task_struct *task;
	struct task_struct *parent;

	e->pid = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = bpf_ktime_get_ns();

	task = (struct task_struct *)bpf_get_current_task();
	parent = task->real_parent;
	if (parent) {
		e->ppid = parent->tgid;
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm),
			&parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}
}

/*
 * looks_like_http checks whether the first bytes of a captured buffer look
 * like an HTTP request line or status line. This is the in-kernel volume
 * filter described in the file header - keeps the ring buffer to genuinely
 * HTTP-shaped traffic instead of every byte a web server process reads.
 */
static __always_inline int looks_like_http(const __u8 *data, __u32 len)
{
	if (len < 4)
		return 0;

	/* Request lines: "GET ", "POST", "PUT ", "HEAD", "DELE"(TE), "OPTI"(ONS), "PATC"(H) */
	if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ')
		return 1;
	if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T')
		return 1;
	if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ')
		return 1;
	if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D')
		return 1;
	if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E')
		return 1;
	if (data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I')
		return 1;
	if (data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C')
		return 1;
	/* Status line: "HTTP/" (response) */
	if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P')
		return 1;

	return 0;
}

/*
 * Per-thread context stashed at read()/recv() entry so the uretprobe knows
 * where the destination buffer is and how large it is. Same pattern as
 * ssl_read_contexts in tls_uprobe.bpf.c.
 */
struct http_read_ctx {
	__u64 buf;
	__u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);  /* pid_tgid */
	__type(value, struct http_read_ctx);
} http_read_contexts SEC(".maps");

/*
 * uprobe/read (entry) and uprobe/recv (entry) - stash the destination buffer
 * pointer so the matching uretprobe can inspect it once data has actually
 * been written into it by the kernel.
 *
 * Signature: ssize_t read(int fd, void *buf, size_t count)
 * Signature: ssize_t recv(int sockfd, void *buf, size_t len, int flags)
 * Arguments (x86_64): rdi=fd, rsi=buf, rdx=count/len
 * Arguments (arm64):  x0=fd, x1=buf, x2=count/len
 */
static __always_inline void stash_read_ctx(struct pt_regs *ctx)
{
	struct http_read_ctx rctx = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

#if defined(__TARGET_ARCH_x86_64)
	rctx.buf = (__u64)PT_REGS_PARM2(ctx);
	rctx.count = (__u64)PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
	rctx.buf = (__u64)PT_REGS_PARM2(ctx);
	rctx.count = (__u64)PT_REGS_PARM3(ctx);
#else
	rctx.buf = (__u64)ctx->si;
	rctx.count = (__u64)ctx->dx;
#endif

	bpf_map_update_elem(&http_read_contexts, &pid_tgid, &rctx, BPF_ANY);
}

SEC("uprobe/read")
int trace_read_entry(struct pt_regs *ctx)
{
	stash_read_ctx(ctx);
	return 0;
}

SEC("uprobe/recv")
int trace_recv_entry(struct pt_regs *ctx)
{
	stash_read_ctx(ctx);
	return 0;
}

/*
 * uretprobe/read and uretprobe/recv - inspect the buffer once the syscall
 * has returned, filter for HTTP-shaped data, and submit only matching events.
 */
static __always_inline int handle_read_ret(struct pt_regs *ctx)
{
	struct http_event *e;
	struct http_read_ctx *rctx;
	__u64 pid_tgid;
	long ret;
	size_t data_len;
	__u8 prefix[4] = {};

	ret = PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	rctx = bpf_map_lookup_elem(&http_read_contexts, &pid_tgid);
	if (!rctx)
		return 0;

	if (!rctx->buf) {
		bpf_map_delete_elem(&http_read_contexts, &pid_tgid);
		return 0;
	}

	/* Peek the first 4 bytes to decide, in-kernel, whether this is worth
	 * capturing at all - avoids reserving ring buffer space for the vast
	 * majority of read()/recv() calls that are not HTTP traffic. */
	if (bpf_probe_read_user(&prefix, sizeof(prefix), (void *)rctx->buf) < 0) {
		bpf_map_delete_elem(&http_read_contexts, &pid_tgid);
		return 0;
	}
	if (!looks_like_http(prefix, sizeof(prefix))) {
		bpf_map_delete_elem(&http_read_contexts, &pid_tgid);
		return 0;
	}

	e = bpf_ringbuf_reserve(&http_events, sizeof(struct http_event), 0);
	if (!e) {
		bpf_map_delete_elem(&http_read_contexts, &pid_tgid);
		return 0;
	}

	fill_http_process_info(e);
	e->type = EVENT_TYPE_HTTP_PLAINTEXT;
	e->direction = HTTP_DIR_REQUEST;
	e->data_len = (__u32)ret;

	data_len = (size_t)ret;
	if (data_len > HTTP_DATA_MAX)
		data_len = HTTP_DATA_MAX;
	e->captured_len = data_len;

	if (data_len > 0) {
		long err = bpf_probe_read_user(&e->data, data_len, (void *)rctx->buf);
		if (err < 0)
			e->captured_len = 0;
	}

	bpf_map_delete_elem(&http_read_contexts, &pid_tgid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uretprobe/read")
int trace_read_ret(struct pt_regs *ctx)
{
	return handle_read_ret(ctx);
}

SEC("uretprobe/recv")
int trace_recv_ret(struct pt_regs *ctx)
{
	return handle_read_ret(ctx);
}

char LICENSE[] SEC("license") = "GPL";
