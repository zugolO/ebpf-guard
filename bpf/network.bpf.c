/*
 * network.bpf.c - eBPF program for TCP connection tracking.
 * Uses kprobe on tcp_connect to capture outbound connections.
 * Supports IPv4 and IPv6 dual-stack.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/*
 * Helper to copy IPv4 address into 16-byte buffer (first 4 bytes)
 */
static __always_inline void copy_ipv4_addr(__u8 *dst, __u32 src)
{
	dst[0] = (__u8)(src & 0xFF);
	dst[1] = (__u8)((src >> 8) & 0xFF);
	dst[2] = (__u8)((src >> 16) & 0xFF);
	dst[3] = (__u8)((src >> 24) & 0xFF);
}

/*
 * Helper to copy IPv6 address from skc_v6_daddr/skc_v6_rcv_saddr
 */
static __always_inline void copy_ipv6_addr(__u8 *dst, struct in6_addr *src)
{
	/* Use bpf_probe_read_kernel to safely read the IPv6 address */
	bpf_probe_read_kernel(dst, 16, src);
}

/*
 * tcp_connect kprobe - captures outbound TCP connection attempts.
 * This is called when a process initiates a TCP connection.
 * Supports both IPv4 and IPv6.
 */
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk)
{
	struct event *e;
	__u16 family;
	
	/* Read address family */
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	
	/* Only handle IPv4 and IPv6 */
	if (family != AF_INET && family != AF_INET6)
		return 0;
	
	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_TCP_CONNECT, 0);
	if (!e)
		return 0;
	
	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_TCP_CONNECT;
	
	/* Fill network-specific data based on address family */
	if (family == AF_INET) {
		/* IPv4: addresses are in skc_rcv_saddr and skc_daddr */
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		
		/* Copy IPv4 addresses into first 4 bytes of 16-byte buffers */
		copy_ipv4_addr(e->network.saddr, saddr);
		copy_ipv4_addr(e->network.daddr, daddr);
		
		e->network.sport = sport;
		e->network.dport = bpf_ntohs(dport); /* Convert to host byte order */
		e->network.proto = IPPROTO_TCP;
		e->network.family = AF_INET;
	} else {
		/* IPv6: addresses are in skc_v6_rcv_saddr and skc_v6_daddr */
		struct in6_addr *saddr6 = &sk->__sk_common.skc_v6_rcv_saddr;
		struct in6_addr *daddr6 = &sk->__sk_common.skc_v6_daddr;
		__u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		
		/* Copy full IPv6 addresses */
		copy_ipv6_addr(e->network.saddr, saddr6);
		copy_ipv6_addr(e->network.daddr, daddr6);
		
		e->network.sport = sport;
		e->network.dport = bpf_ntohs(dport); /* Convert to host byte order */
		e->network.proto = IPPROTO_TCP;
		e->network.family = AF_INET6;
	}
	
	submit_event(e);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
