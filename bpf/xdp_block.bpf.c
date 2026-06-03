// XDP packet filter: drops traffic matching entries in the blocklist maps.
// Attached to a network interface; updated at runtime by the enforcer.
//
// Maps updated from Go via cilium/ebpf (key-value Put/Delete).
// Stats map exposed for Prometheus scraping.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Blocked destination IPs — 16-byte key covers both IPv4 (first 4 bytes) and
// IPv6 (all 16 bytes) in network byte order.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u8[16]);
    __type(value, __u8);
} xdp_blocked_ips SEC(".maps");

// Blocked destination ports (host byte order).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, __u16);
    __type(value, __u8);
} xdp_blocked_ports SEC(".maps");

// Per-CPU stats (indexed by 0).
struct xdp_stats {
    __u64 dropped;
    __u64 passed;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} xdp_stats_map SEC(".maps");

static __always_inline void record_drop(void) {
    __u32 key = 0;
    struct xdp_stats *s = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (s)
        __sync_fetch_and_add(&s->dropped, 1);
}

static __always_inline void record_pass(void) {
    __u32 key = 0;
    struct xdp_stats *s = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (s)
        __sync_fetch_and_add(&s->passed, 1);
}

SEC("xdp")
int xdp_block_fn(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Ethernet header bounds check.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    __u8  daddr[16] = {};
    __u16 dport     = 0;
    __u8  proto     = 0;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        // IPv4: store in first 4 bytes (network byte order) to match Go side.
        *(__u32 *)daddr = iph->daddr;
        proto = iph->protocol;

        __u8 *blocked = bpf_map_lookup_elem(&xdp_blocked_ips, daddr);
        if (blocked && *blocked) {
            record_drop();
            return XDP_DROP;
        }

        // Parse transport header (variable IHL).
        void *transport = (void *)iph + ((iph->ihl & 0xf) << 2);
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = transport;
            if ((void *)(tcph + 1) > data_end)
                return XDP_PASS;
            dport = bpf_ntohs(tcph->dest);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = transport;
            if ((void *)(udph + 1) > data_end)
                return XDP_PASS;
            dport = bpf_ntohs(udph->dest);
        }

    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ipv6h = (void *)(eth + 1);
        if ((void *)(ipv6h + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(daddr, ipv6h->daddr.in6_u.u6_addr8, 16);
        proto = ipv6h->nexthdr;

        __u8 *blocked = bpf_map_lookup_elem(&xdp_blocked_ips, daddr);
        if (blocked && *blocked) {
            record_drop();
            return XDP_DROP;
        }

        void *transport = (void *)(ipv6h + 1);
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = transport;
            if ((void *)(tcph + 1) > data_end)
                return XDP_PASS;
            dport = bpf_ntohs(tcph->dest);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = transport;
            if ((void *)(udph + 1) > data_end)
                return XDP_PASS;
            dport = bpf_ntohs(udph->dest);
        }
    } else {
        return XDP_PASS;
    }

    // Check port blocklist.
    if (dport > 0) {
        __u8 *blocked = bpf_map_lookup_elem(&xdp_blocked_ports, &dport);
        if (blocked && *blocked) {
            record_drop();
            return XDP_DROP;
        }
    }

    record_pass();
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
