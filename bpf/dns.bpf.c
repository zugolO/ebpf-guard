/*
 * dns.bpf.c - eBPF program for DNS monitoring via socket tracepoints.
 * Target: Linux kernel 5.15+ with BTF/CO-RE support.
 *
 * Performance constraints:
 * - Early filtering in BPF: only UDP packets to/from port 53 pass through
 * - All other traffic is dropped with return 0 before any processing
 *
 * Design note: this program does NOT parse the DNS wire format in-kernel.
 * Earlier revisions decoded QNAME (including compression-pointer chasing)
 * inside trace_sendmsg, which repeatedly hit the verifier's instruction
 * limit and required increasingly fragile workarounds (per-CPU scratch
 * maps, barrier_var() pruning hints, masked writes). None of that is
 * necessary: the kernel side only needs to grab the raw UDP payload and
 * hand it to userspace, which can parse arbitrary-complexity DNS messages
 * (including compression pointers) without any verifier constraints.
 *
 * Capture paths: many resolvers (glibc, BIND's `dig`) call connect() once
 * on a UDP socket and then use write()/read() rather than
 * sendto()/sendmsg()/recvfrom() — those plain I/O syscalls carry no
 * destination address, so they're invisible to address-based filtering.
 * trace_connect records connect()ed-to-port-53 fds in dns_socket_map;
 * trace_write, trace_writev, trace_read_enter/exit, and
 * trace_recvfrom_enter/exit consult that map to recognize DNS traffic on
 * those fds. trace_sendmsg/trace_sendto are kept for callers that do pass
 * an explicit destination address.
 */

/* linux/ headers are superseded by vmlinux.h (included via common.h)
 * when doing CO-RE compilation. Do not re-add them here. */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* DNS event type - must match pkg/types/event.go */
#define EVENT_TYPE_DNS 5

/* DNS constants */
#define DNS_PORT 53

/* Maximum number of raw payload bytes captured per packet. Large enough for
 * the overwhelming majority of DNS queries/responses (most are well under
 * 256 bytes); anything larger is truncated rather than dropped, so
 * userspace still gets the header and as much of the message as fits. */
#define DNS_MAX_PAYLOAD 256

/* Power-of-two-minus-one mask used to bound the read size passed to
 * bpf_probe_read_user() in emit_dns_raw_event(). cap_len is computed from a
 * syscall argument that was already checked (>= 12) earlier in the calling
 * tracepoint, but that check doesn't reliably survive: across an inlined
 * call this large (it spans fill_dns_process_info(), which itself calls
 * bpf_get_current_pid_tgid/uid_gid/comm), the compiler can rematerialize
 * cap_len by reloading the raw ctx->args[] value instead of reusing the
 * already-bounds-checked register — which throws away everything the
 * verifier knew about it, including that it's non-negative. `cap_len &=
 * DNS_CAPTURE_LEN_MASK` reasserts a hard bound the verifier can prove from
 * this single instruction, independent of cap_len's prior history. */
#define DNS_CAPTURE_LEN_MASK 0xFF

/* Raw DNS event structure - emitted to ring buffer.
 * Carries the unparsed UDP payload; all DNS wire-format decoding (QNAME,
 * QTYPE, RCODE, answer records, compression pointers) happens in
 * internal/collector/dns.go. */
struct dns_event {
	__u32 type;                    /* EVENT_TYPE_DNS */
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u8  comm[COMM_LEN];
	__u8  direction;                  /* 0 = query (outbound), 1 = response (inbound) */
	__u16 payload_len;                /* Number of valid bytes in payload (<= DNS_MAX_PAYLOAD) */
	__u8  payload[DNS_MAX_PAYLOAD];   /* Raw UDP payload, starting at the DNS header */
} __attribute__((packed));

/* Ring buffer for DNS events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); /* 4MB ring buffer */
} dns_events SEC(".maps");

/* Helper: check if this is a DNS packet (UDP port 53).
 * addr is a user-space pointer (read out of msg->msg_name); every field
 * access must go through bpf_probe_read_user — a direct dereference here
 * triggers "invalid mem access 'inv'" because the verifier cannot treat a
 * value loaded from user memory as a trusted kernel pointer. */
static __always_inline bool is_dns_packet(struct sockaddr *addr, bool is_outbound)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	__u16 family;
	__u16 port;

	/* Only handle AF_INET for now (IPv4 DNS) */
	if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family))
		return false;
	if (family != AF_INET)
		return false;

	/* sin_port is at the same offset for both inbound and outbound use. */
	if (bpf_probe_read_user(&port, sizeof(port), &sin->sin_port))
		return false;

	/* port is in network byte order */
	return port == __builtin_bswap16(DNS_PORT);
}

/* Helper: fill process info into dns_event */
static __always_inline void fill_dns_process_info(struct dns_event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->pid = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;
	e->type = EVENT_TYPE_DNS;
	e->timestamp = bpf_ktime_get_ns();

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* Helper: reserve a dns_event, fill in process info + payload, and submit. */
static __always_inline void emit_dns_raw_event(void *data, __u32 cap_len, __u8 direction)
{
	struct dns_event *evt;

	evt = bpf_ringbuf_reserve(&dns_events, sizeof(*evt), 0);
	if (!evt)
		return;

	fill_dns_process_info(evt);
	evt->direction = direction;

	/* Re-bound cap_len immediately before the dynamic-size read: see the
	 * DNS_CAPTURE_LEN_MASK comment above for why the verifier can't be
	 * trusted to remember cap_len's earlier history at this point. */
	cap_len &= DNS_CAPTURE_LEN_MASK;

	if (bpf_probe_read_user(evt->payload, cap_len, data)) {
		bpf_ringbuf_discard(evt, 0);
		return;
	}

	evt->payload_len = (__u16)cap_len;
	bpf_ringbuf_submit(evt, 0);
}

/*
 * dns_socket_key - composite key identifying a UDP socket fd within a
 * thread group. fd alone is not unique across processes (each process has
 * its own fd namespace), so pid_tgid must be part of the key.
 */
struct dns_socket_key {
	__u64 pid_tgid;
	__u32 fd;
};

/*
 * dns_socket_map - tracks fds that were connect()ed to UDP port 53.
 * Populated by trace_connect, consulted by trace_write/trace_writev (for
 * outbound queries sent via write()/writev() on an already-connected
 * socket — the common glibc/dig pattern) and trace_recvfrom_enter/
 * trace_read_enter (for inbound responses arriving via read()/recvfrom()).
 * LRU so a missed close() doesn't leak entries forever.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dns_socket_key);
	__type(value, __u8);
} dns_socket_map SEC(".maps");

/*
 * dns_pending_io - per-thread scratch recording the destination buffer of
 * an in-flight read()/recvfrom() on a DNS socket, captured at syscall
 * entry (where the buffer pointer is known) and consumed at syscall exit
 * (where the kernel has actually filled the buffer and the return value
 * tells us how many bytes are valid). A thread can only be inside one
 * syscall at a time, so pid_tgid alone is a safe key shared by both
 * read() and recvfrom() — the matching enter/exit pair always agrees on
 * which syscall it was.
 */
struct dns_pending_io {
	void  *buf;
	__u32 fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct dns_pending_io);
} dns_pending_io SEC(".maps");

/* Helper: is fd (in the current thread group) a tracked DNS socket? */
static __always_inline bool is_dns_socket_fd(__u32 fd)
{
	struct dns_socket_key key = {
		.pid_tgid = bpf_get_current_pid_tgid(),
		.fd = fd,
	};
	return bpf_map_lookup_elem(&dns_socket_map, &key) != NULL;
}

/* Tracepoint for connect() — records fds connect()ed to UDP port 53 so
 * later write()/writev()/read()/recvfrom() calls on them can be recognized
 * as DNS traffic even though those syscalls carry no destination address. */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr *addr;
	struct dns_socket_key key;
	__u8 val = 1;

	addr = (struct sockaddr *)ctx->args[1];
	if (!addr)
		return 0;

	if (!is_dns_packet(addr, true))
		return 0;

	key.pid_tgid = bpf_get_current_pid_tgid();
	key.fd = (__u32)ctx->args[0];
	bpf_map_update_elem(&dns_socket_map, &key, &val, BPF_ANY);
	return 0;
}

/* Tracepoint for close() — drop the fd from dns_socket_map. Not strictly
 * required since dns_socket_map is LRU, but it keeps the map accurate
 * immediately rather than waiting for eviction, and avoids a stale fd
 * number (reused by a later, unrelated socket) being misclassified. */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
	struct dns_socket_key key = {
		.pid_tgid = bpf_get_current_pid_tgid(),
		.fd = (__u32)ctx->args[0],
	};
	bpf_map_delete_elem(&dns_socket_map, &key);
	return 0;
}

/* Tracepoint for write() on a connected DNS socket (outbound query). This
 * is the path glibc's resolver and `dig` actually take: connect() once,
 * then write() the query with no destination argument. */
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];
	void *buf;
	long len;

	if (!is_dns_socket_fd(fd))
		return 0;

	buf = (void *)ctx->args[1];
	len = (long)ctx->args[2];
	if (!buf || len < 12)
		return 0;

	emit_dns_raw_event(buf, (__u32)len, 0 /* query */);
	return 0;
}

/* Tracepoint for writev() on a connected DNS socket (outbound query).
 * Only the first iovec is inspected, matching the existing sendmsg
 * handling above — DNS queries are small enough to fit in one iovec in
 * every resolver implementation observed in practice. */
SEC("tracepoint/syscalls/sys_enter_writev")
int trace_writev(struct trace_event_raw_sys_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];
	struct iovec *iov;
	void *data;
	long data_len;

	if (!is_dns_socket_fd(fd))
		return 0;

	iov = (struct iovec *)ctx->args[1];
	if (!iov)
		return 0;

	bpf_probe_read_user(&data, sizeof(data), &iov->iov_base);
	bpf_probe_read_user(&data_len, sizeof(data_len), &iov->iov_len);

	if (!data || data_len < 12)
		return 0;

	emit_dns_raw_event(data, (__u32)data_len, 0 /* query */);
	return 0;
}

/* Tracepoint for read() entry on a connected DNS socket: stash the
 * destination buffer pointer so trace_read_exit can capture the payload
 * once the kernel has actually filled it. */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];
	struct dns_pending_io io;
	__u64 pid_tgid;

	if (!is_dns_socket_fd(fd))
		return 0;

	io.buf = (void *)ctx->args[1];
	io.fd = fd;
	pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&dns_pending_io, &pid_tgid, &io, BPF_ANY);
	return 0;
}

/* Tracepoint for read() exit: ctx->ret is the number of bytes the kernel
 * actually wrote into the buffer captured at entry — that's the inbound
 * DNS response (or as much of it as fit in the caller's buffer). */
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct dns_pending_io *io;
	long ret = ctx->ret;

	io = bpf_map_lookup_elem(&dns_pending_io, &pid_tgid);
	if (!io)
		return 0;

	if (ret >= 12 && io->buf)
		emit_dns_raw_event(io->buf, (__u32)ret, 1 /* response */);

	bpf_map_delete_elem(&dns_pending_io, &pid_tgid);
	return 0;
}

/* Tracepoint for recvfrom() entry on a connected DNS socket — same
 * stash-at-entry / read-at-exit pattern as read() above. */
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];
	struct dns_pending_io io;
	__u64 pid_tgid;

	if (!is_dns_socket_fd(fd))
		return 0;

	io.buf = (void *)ctx->args[1];
	io.fd = fd;
	pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&dns_pending_io, &pid_tgid, &io, BPF_ANY);
	return 0;
}

/* Tracepoint for recvfrom() exit: ctx->ret is the number of bytes
 * received into the buffer captured at entry. */
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct dns_pending_io *io;
	long ret = ctx->ret;

	io = bpf_map_lookup_elem(&dns_pending_io, &pid_tgid);
	if (!io)
		return 0;

	if (ret >= 12 && io->buf)
		emit_dns_raw_event(io->buf, (__u32)ret, 1 /* response */);

	bpf_map_delete_elem(&dns_pending_io, &pid_tgid);
	return 0;
}

/* Tracepoint for UDP sendmsg (outbound DNS queries) */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	struct user_msghdr *msg;
	struct sockaddr *addr;
	struct iovec *iov;
	void *data;
	int data_len;

	/* Get message header from syscall argument */
	msg = (struct user_msghdr *)ctx->args[1];
	if (!msg)
		return 0;

	/* Get destination address */
	bpf_probe_read_user(&addr, sizeof(addr), &msg->msg_name);
	if (!addr)
		return 0;

	/* EARLY FILTER: Only process DNS packets (UDP port 53) */
	if (!is_dns_packet(addr, true))
		return 0;

	/* Get IO vector */
	bpf_probe_read_user(&iov, sizeof(iov), &msg->msg_iov);
	if (!iov)
		return 0;

	/* Get first iov entry data and length */
	bpf_probe_read_user(&data, sizeof(data), &iov->iov_base);
	bpf_probe_read_user(&data_len, sizeof(data_len), &iov->iov_len);

	if (!data || data_len < 12)  /* Minimum DNS header size */
		return 0;

	emit_dns_raw_event(data, (__u32)data_len, 0 /* query */);
	return 0;
}

/* Tracepoint for UDP sendto (alternative outbound path) */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr *addr;
	void *buf;
	int len;

	/* Get destination address from syscall argument */
	addr = (struct sockaddr *)ctx->args[4];
	if (!addr)
		return 0;

	/* EARLY FILTER: Only process DNS packets (UDP port 53) */
	if (!is_dns_packet(addr, true))
		return 0;

	/* Get buffer and length */
	buf = (void *)ctx->args[1];
	len = (int)ctx->args[2];

	if (!buf || len < 12)
		return 0;

	emit_dns_raw_event(buf, (__u32)len, 0 /* query */);
	return 0;
}

/* Note: inbound DNS responses on a connect()ed UDP socket are handled by
 * trace_read_enter/trace_read_exit and trace_recvfrom_enter/
 * trace_recvfrom_exit above. recvmsg() is not separately handled — no
 * resolver implementation observed in practice uses recvmsg() for a
 * connected UDP socket reply; add a sys_enter_recvmsg/sys_exit_recvmsg
 * pair analogous to read/recvfrom above if that's ever seen. */

char _license[] SEC("license") = "GPL";
