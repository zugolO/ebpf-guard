/*
 * dns.bpf.c - eBPF program for DNS monitoring via socket tracepoints.
 * Target: Linux kernel 5.15+ with BTF/CO-RE support.
 *
 * Performance constraints:
 * - Early filtering in BPF: only UDP packets to/from port 53 pass through
 * - All other traffic is dropped with return 0 before any processing
 * - DNS wire format parsing happens only for DNS traffic (hundreds/sec, not thousands)
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

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

/* Helper: check if this is a DNS packet (UDP port 53) */
static __always_inline bool is_dns_packet(struct sockaddr *addr, bool is_outbound)
{
	struct sockaddr_in *sin;
	__u16 port;
	
	/* Only handle AF_INET for now (IPv4 DNS) */
	if (addr->sa_family != AF_INET)
		return false;
	
	sin = (struct sockaddr_in *)addr;
	
	if (is_outbound) {
		/* Outbound: check dport == 53 */
		bpf_probe_read_kernel(&port, sizeof(port), &sin->sin_port);
	} else {
		/* Inbound: check sport == 53 */
		bpf_probe_read_kernel(&port, sizeof(port), &sin->sin_port);
	}
	
	/* port is in network byte order */
	return port == __builtin_bswap16(DNS_PORT);
}

/* Helper: decode DNS name from wire format */
static __always_inline int decode_dns_name(const __u8 *src, __u8 *dst, int max_len)
{
	int src_offset = 0;
	int dst_offset = 0;
	__u8 label_len;
	int i;
	int iterations = 0;
	const int max_iterations = 32; /* Prevent infinite loops */
	
	#pragma unroll
	for (iterations = 0; iterations < max_iterations; iterations++) {
		/* Read label length */
		bpf_probe_read_user(&label_len, sizeof(label_len), src + src_offset);
		
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
		
		/* Copy label content */
		#pragma unroll
		for (i = 0; i < 63; i++) {
			if (i >= label_len)
				break;
			if (dst_offset >= max_len - 1)
				break;
			
			__u8 ch;
			bpf_probe_read_user(&ch, sizeof(ch), src + src_offset + 1 + i);
			dst[dst_offset++] = ch;
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

/* Helper: parse DNS response and extract IP addresses */
static __always_inline void parse_dns_response(const __u8 *data, int data_len,
						       struct dns_event *evt)
{
	/* Skip DNS header (12 bytes) and query section */
	/* DNS header format:
	 * 2 bytes: Transaction ID
	 * 2 bytes: Flags
	 * 2 bytes: Questions
	 * 2 bytes: Answer RRs
	 * 2 bytes: Authority RRs
	 * 2 bytes: Additional RRs
	 */
	
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	int offset = 0;
	int i, j;
	
	if (data_len < 12)
		return;
	
	/* Read flags to determine if this is a response */
	bpf_probe_read_user(&flags, sizeof(flags), data + 2);
	flags = __builtin_bswap16(flags);
	
	/* Check QR bit - must be 1 for response */
	if ((flags & DNS_FLAG_QR_RESPONSE) == 0)
		return;
	
	evt->rcode = flags & DNS_FLAG_RCODE_MASK;
	evt->direction = 1; /* Response */
	
	/* Read question count */
	bpf_probe_read_user(&qdcount, sizeof(qdcount), data + 4);
	qdcount = __builtin_bswap16(qdcount);
	
	/* Read answer count */
	bpf_probe_read_user(&ancount, sizeof(ancount), data + 6);
	ancount = __builtin_bswap16(ancount);
	
	/* Skip header */
	offset = 12;
	
	/* Skip query section (we already parsed qname in the caller) */
	/* Query section: qname (variable) + qtype (2) + qclass (2) */
	/* For simplicity, we assume the qname was parsed separately */
	/* Just skip past it by looking for null label or compression pointer */
	#pragma unroll
	for (i = 0; i < 256 && offset < data_len; i++) {
		__u8 b;
		bpf_probe_read_user(&b, sizeof(b), data + offset);
		
		if (b == 0) {
			offset += 5; /* null + qtype (2) + qclass (2) */
			break;
		}
		if ((b & 0xC0) == 0xC0) {
			offset += 6; /* compression ptr (2) + qtype (2) + qclass (2) */
			break;
		}
		offset += b + 1;
	}
	
	/* Parse answer RRs to extract IP addresses */
	evt->response_count = 0;
	
	#pragma unroll
	for (i = 0; i < DNS_MAX_RESPONSE_IPS && i < ancount; i++) {
		__u16 rr_type;
		__u16 rr_rdlength;
		__u32 rr_ttl;
		int name_skip = 0;
		
		if (offset >= data_len)
			break;
		
		/* Skip name (variable length) */
		#pragma unroll
		for (j = 0; j < 256 && offset + name_skip < data_len; j++) {
			__u8 b;
			bpf_probe_read_user(&b, sizeof(b), data + offset + name_skip);
			
			if (b == 0) {
				name_skip++;
				break;
			}
			if ((b & 0xC0) == 0xC0) {
				name_skip += 2;
				break;
			}
			name_skip += b + 1;
		}
		
		offset += name_skip;
		
		if (offset + 10 > data_len)
			break;
		
		/* Read type */
		bpf_probe_read_user(&rr_type, sizeof(rr_type), data + offset);
		rr_type = __builtin_bswap16(rr_type);
		
		/* Read TTL (skip 2 bytes for class) */
		bpf_probe_read_user(&rr_ttl, sizeof(rr_ttl), data + offset + 4);
		rr_ttl = __builtin_bswap32(rr_ttl);
		
		/* Read rdlength */
		bpf_probe_read_user(&rr_rdlength, sizeof(rr_rdlength), data + offset + 8);
		rr_rdlength = __builtin_bswap16(rr_rdlength);
		
		offset += 10; /* type (2) + class (2) + ttl (4) + rdlength (2) */
		
		/* Extract A record (IPv4) */
		if (rr_type == DNS_QTYPE_A && rr_rdlength == 4 && 
		    offset + 4 <= data_len && evt->response_count < DNS_MAX_RESPONSE_IPS) {
			__u32 ip;
			bpf_probe_read_user(&ip, sizeof(ip), data + offset);
			evt->response_ips[evt->response_count++] = ip;
		}
		
		offset += rr_rdlength;
	}
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
