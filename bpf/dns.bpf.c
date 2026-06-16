/*
 * dns.bpf.c - eBPF program for DNS monitoring via socket tracepoints.
 * Target: Linux kernel 5.15+ with BTF/CO-RE support.
 *
 * Performance constraints:
 * - Early filtering in BPF: only UDP packets to/from port 53 pass through
 * - All other traffic is dropped with return 0 before any processing
 * - DNS wire format parsing happens only for DNS traffic (hundreds/sec, not thousands)
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
#define DNS_MAX_NAME_LEN 128
#define DNS_MAX_RESPONSE_IPS 8

/* DNS header flags */
#define DNS_FLAG_QR_RESPONSE 0x8000  /* Query/Response: 1 = response */
#define DNS_FLAG_OPCODE_MASK 0x7800  /* Opcode mask */
#define DNS_FLAG_RCODE_MASK 0x000f   /* Response code mask */

/* DNS QTYPE values */
#define DNS_QTYPE_A     1
#define DNS_QTYPE_NS    2
#define DNS_QTYPE_CNAME 5
#define DNS_QTYPE_SOA   6
#define DNS_QTYPE_PTR   12
#define DNS_QTYPE_MX    15
#define DNS_QTYPE_TXT   16
#define DNS_QTYPE_AAAA  28
#define DNS_QTYPE_SRV   33
#define DNS_QTYPE_ANY   255

/* DNS event structure - emitted to ring buffer */
struct dns_event {
	__u32 type;                    /* EVENT_TYPE_DNS */
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u8  comm[COMM_LEN];
	
	/* DNS-specific fields */
	__u8  qname[DNS_MAX_NAME_LEN]; /* Query name (domain) */
	__u16 qtype;                   /* Query type (A, AAAA, TXT, etc.) */
	__u16 rcode;                   /* Response code (0 = success) */
	__u8  direction;               /* 0 = query (outbound), 1 = response (inbound) */
	__u8  qname_len;               /* Actual length of qname */
	
	/* Response data (only valid for inbound responses) */
	__u8  response_count;          /* Number of response IPs (0-8) */
	__u32 response_ips[DNS_MAX_RESPONSE_IPS]; /* Response IPv4 addresses */
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

/* Helper: decode DNS name from wire format.
 * Each label is read with a single bulk bpf_probe_read_user call instead of
 * a byte-by-byte unrolled loop — the previous nested #pragma unroll (32
 * outer x 63 inner iterations, each issuing its own probe_read call) pushed
 * the verifier past 1M processed instructions on trace_sendmsg. */
static __always_inline int decode_dns_name(const __u8 *src, __u8 *dst, int max_len)
{
	int src_offset = 0;
	int dst_offset = 0;
	__u8 label_len;
	int iterations = 0;
	const int max_iterations = 16; /* DNS names rarely exceed a handful of labels */

	#pragma unroll
	for (iterations = 0; iterations < max_iterations; iterations++) {
		/* Read label length */
		if (bpf_probe_read_user(&label_len, sizeof(label_len), src + src_offset))
			break;

		/* End of name (null label) */
		if (label_len == 0) {
			src_offset++;
			break;
		}

		/* Check for compression pointer (0xC0) - skip compressed names */
		if ((label_len & 0xC0) == 0xC0) {
			/* Compression pointer - we don't follow it, just skip */
			src_offset += 2;
			break;
		}

		/* Check bounds */
		if (label_len > 63 || src_offset + label_len + 1 > 512) {
			break;
		}

		/* Add dot separator if not first label */
		if (dst_offset > 0 && dst_offset < max_len - 1) {
			dst[dst_offset++] = '.';
		}

		/* Bail out (no write) if the label wouldn't fit, rather than
		 * clamping copy_len down to fit. The verifier can't correlate a
		 * clamped copy_len with dst_offset across unrolled iterations, so
		 * it conservatively assumes both can be at their independent max
		 * at once, putting the write past the end of dst. A hard
		 * pre-check keeps the bound on dst_offset + label_len provable. */
		if (dst_offset + label_len > max_len - 1)
			break;

		if (bpf_probe_read_user(dst + dst_offset, label_len, src + src_offset + 1) == 0) {
			dst_offset += label_len;
		}

		src_offset += label_len + 1;

		/* Safety check for offset overflow */
		if (src_offset > 512)
			break;
	}

	/* Null terminate */
	if (dst_offset < max_len)
		dst[dst_offset] = '\0';

	return dst_offset;
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

/* Tracepoint for UDP sendmsg (outbound DNS queries) */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	struct dns_event *evt;
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
	
	/* Reserve event in ring buffer */
	evt = bpf_ringbuf_reserve(&dns_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	
	/* Fill process info */
	fill_dns_process_info(evt);
	evt->direction = 0; /* Query (outbound) */
	evt->response_count = 0;
	
	/* Parse DNS query from data */
	/* DNS query format after header:
	 * - QNAME (variable length, encoded)
	 * - QTYPE (2 bytes)
	 * - QCLASS (2 bytes)
	 */
	
	/* Skip DNS header (12 bytes) and decode QNAME */
	evt->qname_len = decode_dns_name(data + 12, evt->qname, DNS_MAX_NAME_LEN);
	
	/* Read QTYPE (after QNAME) - approximate position */
	/* For simplicity, we read from a fixed offset after typical QNAME length */
	if (data_len > 14) {
		__u16 qtype;
		/* Try to read QTYPE from various offsets based on common domain lengths */
		int qtype_offset = 12 + evt->qname_len + 1; /* header + qname + null */
		if (qtype_offset + 2 <= data_len && qtype_offset < 512) {
			bpf_probe_read_user(&qtype, sizeof(qtype), data + qtype_offset);
			evt->qtype = __builtin_bswap16(qtype);
		} else {
			evt->qtype = 0;
		}
	} else {
		evt->qtype = 0;
	}
	
	evt->rcode = 0; /* No response code for queries */
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* Tracepoint for UDP sendto (alternative outbound path) */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
	struct dns_event *evt;
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
	
	/* Reserve event in ring buffer */
	evt = bpf_ringbuf_reserve(&dns_events, sizeof(*evt), 0);
	if (!evt)
		return 0;
	
	/* Fill process info */
	fill_dns_process_info(evt);
	evt->direction = 0; /* Query (outbound) */
	evt->response_count = 0;
	
	/* Parse DNS query */
	evt->qname_len = decode_dns_name(buf + 12, evt->qname, DNS_MAX_NAME_LEN);
	
	/* Read QTYPE */
	if (len > 14) {
		__u16 qtype;
		int qtype_offset = 12 + evt->qname_len + 1;
		if (qtype_offset + 2 <= len && qtype_offset < 512) {
			bpf_probe_read_user(&qtype, sizeof(qtype), buf + qtype_offset);
			evt->qtype = __builtin_bswap16(qtype);
		} else {
			evt->qtype = 0;
		}
	} else {
		evt->qtype = 0;
	}
	
	evt->rcode = 0;
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

/* Tracepoint for UDP recvmsg (inbound DNS responses) */
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_recvmsg(struct trace_event_raw_sys_exit *ctx)
{
	struct dns_event *evt;
	struct user_msghdr *msg;
	struct sockaddr *addr;
	struct iovec *iov;
	void *data;
	int data_len;
	long ret;
	
	/* Check return value - must be successful */
	ret = ctx->ret;
	if (ret < 12)  /* Minimum DNS header size */
		return 0;
	
	/* Get message header from syscall argument (stored in probe) */
	/* Note: for sys_exit, we need to read the msg header from user space */
	/* This is a simplified version - in production, you'd use a kprobe on udp_recvmsg */
	
	/* For now, we skip detailed response parsing in tracepoint due to complexity */
	/* Full implementation would use kprobe on udp_recvmsg or skb tracepoint */
	
	return 0;
}

/* Alternative: kprobe on udp_rcv for kernel-space packet inspection */
/* This provides access to the skb without userspace pointer complexity */

char _license[] SEC("license") = "GPL";
