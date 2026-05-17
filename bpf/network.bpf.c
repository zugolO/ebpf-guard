/*
 * network.bpf.c - eBPF program for TCP connection tracking.
 * Uses kprobe on tcp_connect (outbound) and tcp_close (close with duration).
 * Supports IPv4 and IPv6 dual-stack.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/*
 * conn_start_map: tracks per-socket connect timestamp.
 * Key: socket pointer (u64), Value: ktime_get_ns() at tcp_connect.
 * Entries are removed in tcp_close to avoid unbounded growth.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);   /* sock pointer */
	__type(value, __u64); /* connect timestamp (ns) */
} conn_start_map SEC(".maps");

/*
 * conn_meta_map: stores connection tuple at connect time so tcp_close can
 * emit the full tuple without re-reading (sock fields may be cleared).
 * Key: sock pointer, Value: packed tuple struct.
 */
struct conn_tuple {
	__u8  saddr[16];
	__u8  daddr[16];
	__u16 sport;
	__u16 dport;
	__u8  family;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);              /* sock pointer */
	__type(value, struct conn_tuple);
} conn_meta_map SEC(".maps");

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
 * Also stores the connect timestamp and tuple for duration tracking in tcp_close.
 */
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk)
{
	struct event *e;
	__u16 family;
	__u64 sk_ptr = (__u64)(unsigned long)sk;
	__u64 ts = bpf_ktime_get_ns();

	/* Read address family */
	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	/* Only handle IPv4 and IPv6 */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	/* Store connect timestamp for duration calculation in tcp_close. */
	bpf_map_update_elem(&conn_start_map, &sk_ptr, &ts, BPF_ANY);

	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_TCP_CONNECT, 0);
	if (!e)
		goto store_meta;

	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_TCP_CONNECT;

	if (family == AF_INET) {
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

		copy_ipv4_addr(e->network.saddr, saddr);
		copy_ipv4_addr(e->network.daddr, daddr);
		e->network.sport  = sport;
		e->network.dport  = bpf_ntohs(dport);
		e->network.proto  = IPPROTO_TCP;
		e->network.family = AF_INET;
	} else {
		struct in6_addr *saddr6 = &sk->__sk_common.skc_v6_rcv_saddr;
		struct in6_addr *daddr6 = &sk->__sk_common.skc_v6_daddr;
		__u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

		copy_ipv6_addr(e->network.saddr, saddr6);
		copy_ipv6_addr(e->network.daddr, daddr6);
		e->network.sport  = sport;
		e->network.dport  = bpf_ntohs(dport);
		e->network.proto  = IPPROTO_TCP;
		e->network.family = AF_INET6;
	}

	submit_event(e);

store_meta:;
	/* Store tuple so tcp_close can emit it without re-reading the sock. */
	struct conn_tuple meta = {};
	meta.family = (__u8)family;
	if (family == AF_INET) {
		__u32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		copy_ipv4_addr(meta.saddr, s);
		copy_ipv4_addr(meta.daddr, d);
		meta.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		meta.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	} else {
		copy_ipv6_addr(meta.saddr, &sk->__sk_common.skc_v6_rcv_saddr);
		copy_ipv6_addr(meta.daddr, &sk->__sk_common.skc_v6_daddr);
		meta.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		meta.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	}
	bpf_map_update_elem(&conn_meta_map, &sk_ptr, &meta, BPF_ANY);

	return 0;
}

/*
 * tcp_close kprobe - emits EVENT_NET_CLOSE with connection duration.
 * Duration is encoded in syscall.args[0] (nanoseconds) to avoid
 * extending the wire-format struct; family/ports in args[1-3].
 *
 * Wire encoding in syscall union slots:
 *   args[0] = duration_ns
 *   args[1] = (dport << 16) | sport
 *   args[2] = family
 *   args[3..4] = saddr (16 bytes packed as two u64)
 *   args[5]    = daddr low 8 bytes (IPv4 only needs 4 bytes here)
 * For full tuple the collector reads the separate conn_meta ring-buf event.
 *
 * Simpler approach: emit a standard event with type=EVENT_NET_CLOSE and
 * encode duration_ns in syscall.args[0]; tuple in network union fields
 * (re-read from sock — still valid at tcp_close entry).
 */
SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_tcp_close, struct sock *sk, long timeout)
{
	__u64 sk_ptr = (__u64)(unsigned long)sk;
	__u64 *start_ts;
	struct conn_tuple *meta;
	__u64 now = bpf_ktime_get_ns();
	__u64 duration_ns = 0;
	struct event *e;

	start_ts = bpf_map_lookup_elem(&conn_start_map, &sk_ptr);
	if (!start_ts) {
		/* Not a connection we tracked (e.g. incoming). */
		return 0;
	}
	duration_ns = now - *start_ts;

	/* Clean up tracking maps. */
	bpf_map_delete_elem(&conn_start_map, &sk_ptr);

	meta = bpf_map_lookup_elem(&conn_meta_map, &sk_ptr);

	e = reserve_event();
	if (!e) {
		bpf_map_delete_elem(&conn_meta_map, &sk_ptr);
		return 0;
	}

	fill_process_info(e);
	e->type = EVENT_TYPE_NET_CLOSE;

	/* Encode duration and tuple in the network union. */
	if (meta) {
		__builtin_memcpy(e->network.saddr, meta->saddr, 16);
		__builtin_memcpy(e->network.daddr, meta->daddr, 16);
		e->network.sport  = meta->sport;
		e->network.dport  = meta->dport;
		e->network.proto  = IPPROTO_TCP;
		e->network.family = meta->family;
		bpf_map_delete_elem(&conn_meta_map, &sk_ptr);
	} else {
		/* Fallback: re-read from sock (fields usually still valid). */
		__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
		e->network.family = (__u8)family;
		if (family == AF_INET) {
			__u32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
			__u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
			copy_ipv4_addr(e->network.saddr, s);
			copy_ipv4_addr(e->network.daddr, d);
		}
		e->network.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		e->network.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		e->network.proto = IPPROTO_TCP;
	}

	/* Encode duration_ns in syscall.args[0] (reuse union slot). */
	e->syscall.args[0] = duration_ns;

	submit_event(e);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
