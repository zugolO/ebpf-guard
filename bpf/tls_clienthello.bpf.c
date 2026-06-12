/*
 * tls_clienthello.bpf.c — TLS ClientHello capture for JA3/JA4 fingerprinting.
 *
 * Attaches a kprobe to __x64_sys_sendto to capture outbound TLS ClientHello
 * packets at the socket level. The ClientHello is the first TLS record sent
 * during the handshake and is unencrypted, making it the ideal source for
 * JA3/JA4 fingerprint computation.
 *
 * JA3/JA4 fingerprints identify C2 frameworks (Cobalt Strike, Sliver, Mythic)
 * without decrypting traffic by examining TLS version, cipher suites,
 * extensions, and elliptic curve parameters from the ClientHello.
 *
 * Target: Linux kernel 5.15+
 */
#include "common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Maximum ClientHello bytes to capture. 512 bytes covers the full handshake
 * including all cipher suites and extensions for typical clients.  Larger
 * captures are truncated. */
#define TLS_CH_CAPTURE_MAX 512

/*
 * tls_clienthello_event — wire format for captured ClientHello data.
 * Must match TlsClientHelloRawEvent in internal/bpf/syscall_bpf_gen.go.
 *
 * Wire layout (packed, little-endian):
 *
 *   [0   ] type          uint32    (4)
 *   [4   ] timestamp     uint64    (8)
 *   [12  ] pid           uint32    (4)
 *   [16  ] tgid          uint32    (4)
 *   [20  ] ppid          uint32    (4)
 *   [24  ] uid           uint32    (4)
 *   [28  ] comm          [16]byte  (16)
 *   [44  ] parent_comm   [16]byte  (16)
 *   [60  ] dport         uint16    (2)   // network-byte-order destination port
 *   [62  ] captured_len  uint16    (2)   // bytes actually captured
 *   [64  ] original_len  uint32    (4)   // original sendto length
 *   [68  ] data          [512]byte (512) // captured ClientHello bytes
 *
 * Total: 580 bytes
 */
struct tls_clienthello_event {
	__u32 type;
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u8  comm[16];
	__u8  parent_comm[16];
	__u16 dport;           /* destination port (network byte order) */
	__u16 captured_len;    /* bytes copied into data[] */
	__u32 original_len;    /* original sendto length before truncation */
	__u8  data[TLS_CH_CAPTURE_MAX];
};

/* Dedicated ring buffer for ClientHello events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} tls_clienthello_events SEC(".maps");

/*
 * Helper: fill process identity into a tls_clienthello_event.
 */
static __always_inline void fill_ch_process_info(struct tls_clienthello_event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct task_struct *task;
	struct task_struct *parent;

	e->pid  = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->uid  = (__u32)uid_gid;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = bpf_ktime_get_ns();

	task = (struct task_struct *)bpf_get_current_task();
	if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) == 0) {
		e->ppid = (__u32)BPF_CORE_READ(parent, tgid);
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm),
				      parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}
}

/*
 * kprobe on __x64_sys_sendto(int fd, void __user *buff, size_t len, ...)
 *
 * Inspects the outbound data for a TLS ClientHello record:
 *   - First byte == 0x16 (TLS ContentType: Handshake)
 *   - Byte 5 == 0x01 (HandshakeType: ClientHello)
 *
 * When found, captures the first TLS_CH_CAPTURE_MAX bytes and submits
 * the event to the tls_clienthello_events ring buffer.
 */
SEC("kprobe/__x64_sys_sendto")
int BPF_KPROBE(trace_sendto, int fd, void __user *buf, size_t len,
	       int flags, struct sockaddr __user *addr, int addrlen)
{
	struct tls_clienthello_event *e;
	__u8 peek[6];
	__u32 cap_len;

	/* Minimum size check: need at least a TLS record header (5 bytes)
	 * plus the handshake header (4 bytes) + handshake type (1 byte) */
	if (len < 10)
		return 0;

	/* Read first 6 bytes from userspace to check for ClientHello pattern.
	 * bpf_probe_read_user returns 0 on success, negative on fault. */
	if (bpf_probe_read_user(peek, sizeof(peek), buf) < 0)
		return 0;

	/* Check TLS record type: 0x16 = Handshake */
	if (peek[0] != 0x16)
		return 0;

	/* Check that this looks like a valid TLS version
	 * (0x03xx where xx is 0x00-0x04 for known TLS/SSL versions) */
	if (peek[1] != 0x03)
		return 0;
	if (peek[2] > 0x04)
		return 0;

	/* Check HandshakeType: 0x01 = ClientHello */
	if (peek[5] != 0x01)
		return 0;

	/* Confirmed ClientHello — reserve ring buffer space */
	e = bpf_ringbuf_reserve(&tls_clienthello_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_TYPE_TLS;

	cap_len = (__u32)(len > TLS_CH_CAPTURE_MAX ? TLS_CH_CAPTURE_MAX : len);
	e->captured_len = (__u16)cap_len;
	e->original_len = (__u32)len;

	/* Copy ClientHello data from userspace */
	if (bpf_probe_read_user(e->data, cap_len, buf) < 0)
		e->captured_len = 0;

	fill_ch_process_info(e);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
