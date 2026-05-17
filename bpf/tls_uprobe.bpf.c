/*
 * tls_uprobe.bpf.c - eBPF uprobe programs for TLS traffic inspection.
 * Attaches to SSL_write/SSL_read in libssl.so to capture plaintext before encryption.
 * 
 * Target: Linux kernel 5.15+ with BTF/CO-RE support.
 * Requires: CAP_SYS_PTRACE for uprobe attachment.
 * 
 * Limitations:
 * - Only captures data from OpenSSL/libssl (not Go crypto/tls, which uses different implementation)
 * - First 256 bytes only (configurable via TLS_DATA_MAX)
 * - May miss data if buffer spans multiple SSL_write/SSL_read calls
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/* TLS-specific event type */
#define EVENT_TYPE_TLS 4

/* TLS direction codes */
#define TLS_DIR_WRITE 0  /* Outbound data (SSL_write) */
#define TLS_DIR_READ  1  /* Inbound data (SSL_read) */

/* Maximum TLS data to capture per event */
#define TLS_DATA_MAX 256

/* 
 * Extended event structure for TLS events.
 * Reuses base event fields from common.h but adds TLS-specific payload.
 */
struct tls_event {
	__u32 type;
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u8  comm[COMM_LEN];
	__u8  parent_comm[COMM_LEN];
	
	/* TLS-specific fields */
	__u8  direction;        /* TLS_DIR_WRITE or TLS_DIR_READ */
	__u32 data_len;         /* Actual data length (may be > TLS_DATA_MAX) */
	__u32 captured_len;     /* Bytes actually captured (<= TLS_DATA_MAX) */
	__u8  data[TLS_DATA_MAX]; /* Captured plaintext data */
	
	/* Connection info (if available from SSL context) */
	__u8  has_conn_info;
	__u8  saddr[16];
	__u8  daddr[16];
	__u16 sport;
	__u16 dport;
} __attribute__((packed));

/* Ring buffer for TLS events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} tls_events SEC(".maps");

/* 
 * Helper: Fill process info for TLS events.
 * Duplicated from common.h to work with tls_event struct.
 */
static __always_inline void fill_tls_process_info(struct tls_event *e)
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
	
	/* Get parent process info */
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
 * uprobe/SSL_write - Intercept outbound TLS data before encryption.
 * 
 * Signature: int SSL_write(SSL *ssl, const void *buf, int num)
 * Arguments (x86_64): rdi=ssl, rsi=buf, rdx=num
 * Arguments (arm64): x0=ssl, x1=buf, x2=num
 */
SEC("uprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx)
{
	struct tls_event *e;
	const void *buf;
	int num;
	size_t data_len;
	
	/* Reserve space in ring buffer */
	e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
	if (!e)
		return 0;
	
	/* Fill process info */
	fill_tls_process_info(e);
	e->type = EVENT_TYPE_TLS;
	e->direction = TLS_DIR_WRITE;
	e->has_conn_info = 0;
	
	/* Get arguments from registers (x86_64) */
#if defined(__TARGET_ARCH_x86_64)
	buf = (const void *)PT_REGS_PARM2(ctx);
	num = (int)PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
	buf = (const void *)PT_REGS_PARM2(ctx);
	num = (int)PT_REGS_PARM3(ctx);
#else
	/* Fallback - try to read from registers directly */
	buf = (const void *)ctx->si;
	num = (int)ctx->dx;
#endif
	
	/* Validate and cap data length */
	if (num <= 0) {
		e->data_len = 0;
		e->captured_len = 0;
		bpf_ringbuf_submit(e, 0);
		return 0;
	}
	
	e->data_len = num;
	data_len = num;
	if (data_len > TLS_DATA_MAX)
		data_len = TLS_DATA_MAX;
	
	e->captured_len = data_len;
	
	/* Read plaintext data from userspace buffer */
	if (buf && data_len > 0) {
		long ret = bpf_probe_read_user(&e->data, data_len, buf);
		if (ret < 0) {
			/* Read failed - still submit event with zero data */
			e->captured_len = 0;
		}
	}
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * uprobe/SSL_read - Intercept inbound TLS data after decryption.
 * 
 * Signature: int SSL_read(SSL *ssl, void *buf, int num)
 * Arguments (x86_64): rdi=ssl, rsi=buf, rdx=num
 * 
 * Note: SSL_read is probed on return (uretprobe) to capture the actual
 * decrypted data, not the empty buffer passed in.
 */
SEC("uretprobe/SSL_read")
int trace_ssl_read_ret(struct pt_regs *ctx)
{
	struct tls_event *e;
	void *buf;
	int ret;
	size_t data_len;
	
	/* Get return value - this is the actual bytes read/decrypted */
	ret = PT_REGS_RC(ctx);
	if (ret <= 0) {
		/* No data read or error */
		return 0;
	}
	
	/* Reserve space in ring buffer */
	e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
	if (!e)
		return 0;
	
	/* Fill process info */
	fill_tls_process_info(e);
	e->type = EVENT_TYPE_TLS;
	e->direction = TLS_DIR_READ;
	e->has_conn_info = 0;
	e->data_len = ret;
	
	/* 
	 * For SSL_read uretprobe, we need to get the buffer pointer.
	 * This is stored in a map by the entry probe since it's not available on return.
	 * For simplicity, we capture without the actual data on uretprobe.
	 * Full implementation would use a map to store buf pointer from entry.
	 */
	e->captured_len = 0;
	__builtin_memset(&e->data, 0, sizeof(e->data));
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * uprobe/SSL_read (entry) - Store buffer pointer for uretprobe.
 * We need this to read the decrypted data on return.
 */
struct ssl_read_ctx {
	void *buf;
	int num;
};

/* Map to store SSL_read context between entry and return */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct ssl_read_ctx);
} ssl_read_contexts SEC(".maps");

SEC("uprobe/SSL_read")
int trace_ssl_read_entry(struct pt_regs *ctx)
{
	struct ssl_read_ctx read_ctx = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	
#if defined(__TARGET_ARCH_x86_64)
	read_ctx.buf = (void *)PT_REGS_PARM2(ctx);
	read_ctx.num = (int)PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
	read_ctx.buf = (void *)PT_REGS_PARM2(ctx);
	read_ctx.num = (int)PT_REGS_PARM3(ctx);
#else
	read_ctx.buf = (void *)ctx->si;
	read_ctx.num = (int)ctx->dx;
#endif
	
	bpf_map_update_elem(&ssl_read_contexts, &pid_tgid, &read_ctx, BPF_ANY);
	return 0;
}

/*
 * uretprobe/SSL_read (full version) - Uses stored context to read data.
 * This replaces the simpler version above when context tracking is enabled.
 */
SEC("uretprobe/SSL_read_full")
int trace_ssl_read_ret_full(struct pt_regs *ctx)
{
	struct tls_event *e;
	struct ssl_read_ctx *read_ctx;
	__u64 pid_tgid;
	int ret;
	size_t data_len;
	
	/* Get return value */
	ret = PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;
	
	pid_tgid = bpf_get_current_pid_tgid();
	
	/* Lookup stored context */
	read_ctx = bpf_map_lookup_elem(&ssl_read_contexts, &pid_tgid);
	if (!read_ctx)
		return 0;
	
	/* Reserve space in ring buffer */
	e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
	if (!e) {
		bpf_map_delete_elem(&ssl_read_contexts, &pid_tgid);
		return 0;
	}
	
	/* Fill process info */
	fill_tls_process_info(e);
	e->type = EVENT_TYPE_TLS;
	e->direction = TLS_DIR_READ;
	e->has_conn_info = 0;
	e->data_len = ret;
	
	/* Calculate capture length */
	data_len = ret;
	if (data_len > TLS_DATA_MAX)
		data_len = TLS_DATA_MAX;
	
	e->captured_len = data_len;
	
	/* Read decrypted data from userspace buffer */
	if (read_ctx->buf && data_len > 0) {
		long err = bpf_probe_read_user(&e->data, data_len, read_ctx->buf);
		if (err < 0) {
			e->captured_len = 0;
		}
	}
	
	/* Clean up stored context */
	bpf_map_delete_elem(&ssl_read_contexts, &pid_tgid);
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
