/* lsm.bpf.c — eBPF LSM hooks for pre-execution enforcement and detection
 *
 * Hooks implemented:
 *   Sprint 22.0: bpf_file_open, bpf_socket_connect, bpf_task_kill
 *   Sprint 33.0: kernel_module_request, kernel_read_file (kmod load detection)
 *
 * Requires kernel 5.7+ with CONFIG_BPF_LSM=y.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#ifndef EACCES
#define EACCES 13
#endif
#ifndef EPERM
#define EPERM 1
#endif

/* Max path bytes hashed by fnv32a() / sandbox_path_allowed() */
#define PATH_HASH_MAX 128

/* LSM blocklist map: PID -> blocked indicator (used by socket_connect hook) */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   /* PID */
	__type(value, __u8);  /* 1 = blocked */
} lsm_blocklist SEC(".maps");

/* Per-path blocklist: FNV-32a hash of the path string -> blocked flag.
 * Checked on every file_open.  Populated by the Go enforcer from rule
 * conditions and from the enforcer.lsm_path_blocklist config list.
 * Max 256 entries; rotate old entries via BPF map delete on the Go side.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);   /* FNV-32a of path string */
	__type(value, __u8);  /* 1 = blocked */
} path_blocklist SEC(".maps");

/* Agent whitelist: PIDs that should never be blocked (the agent itself) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);   /* PID */
	__type(value, __u8);  /* 1 = whitelisted */
} lsm_agent_whitelist SEC(".maps");

/* Sandbox self-protection (issue #255, session 2, item 1).
 * PIDs (tgids) that a sandboxed task must not be able to signal — the
 * ebpf-guard agent and its worker tree. Populated by internal/sandbox
 * (Manager.ProtectPID). Distinct from lsm_agent_whitelist, which exempts the
 * agent as a *sender*; this map protects the agent as a *target*. Consulted by
 * lsm_task_kill only when the sender is inside a sandboxed cgroup, so an empty
 * map (or no active sandbox) costs nothing on the ordinary signalling path. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);   /* protected tgid */
	__type(value, __u8);  /* 1 = protected */
} sandbox_protected_pids SEC(".maps");

/* LSM action stats: hook type -> count */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 16);
	__type(key, __u32);   /* stat index */
	__type(value, __u64); /* count */
} lsm_stats SEC(".maps");

/* Stat indices */
#define LSM_STAT_FILE_OPEN_ALLOW  0
#define LSM_STAT_FILE_OPEN_BLOCK  1
#define LSM_STAT_SOCK_CONN_ALLOW  2
#define LSM_STAT_SOCK_CONN_BLOCK  3
#define LSM_STAT_TASK_KILL_ALLOW  4
#define LSM_STAT_TASK_KILL_BLOCK  5
#define LSM_STAT_KMOD_LOAD        6
#define LSM_STAT_CGROUP_ESC       7
/* session 2 — escape-primitive containment for sandboxed cgroups */
#define LSM_STAT_SBX_BPF_BLOCK    8
#define LSM_STAT_SBX_PTRACE_BLOCK 9
#define LSM_STAT_SBX_MOUNT_BLOCK  10
#define LSM_STAT_SBX_MODULE_BLOCK 11

/* Ring buffer for kmod / cgroup-escape events (separate from syscall ring buffer
 * in common.h to avoid contention on the hot syscall path). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024); /* 64KB is sufficient for infrequent events */
} lsm_events SEC(".maps");

/* Per-PID initial cgroup ID recorded at exec time.
 * Used by the cgroup_attach_task hook to detect namespace migration.
 * Key: PID (u32), Value: cgroup_id (u64).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} pid_initial_cgroup SEC(".maps");

/* -------------------------------------------------------------------------
 * AI-agent sandbox (issue #255) — cgroup-scoped positive (allow) policy.
 *
 * Direction is inverted vs. the blocklists above: a cgroup registered in
 * sandbox_cgroups is deny-by-default and may only exec / open / connect to
 * what its profile allow-lists. Maps are populated by internal/sandbox.
 * -------------------------------------------------------------------------
 */

#define SANDBOX_MODE_AUDIT   0
#define SANDBOX_MODE_ENFORCE 1

/* Profile flag bits (bits 8-15 of the sandbox_cgroups value) */
#define SBX_F_PORTS_FILTER  (1 << 0)  /* profile lists egress ports (empty = all allowed) */

/* Access bits for sandbox_path_policy values */
#define SBX_ALLOW_READ  (1 << 0)
#define SBX_ALLOW_WRITE (1 << 1)
#define SBX_ALLOW_EXEC  (1 << 2)
#define SBX_DENY        (1 << 3)  /* denied_paths override — beats any allow */

/* file->f_mode bits (include/linux/fs.h) */
#define SBX_FMODE_WRITE 0x2
#define SBX_FMODE_EXEC  0x20

/* Max cgroup ancestor levels walked when matching a task to a sandbox.
 * Kubernetes pod cgroups sit at depth ~5-7; 12 covers nested slices. */
#define SBX_MAX_CGROUP_LEVELS 12

/* sandbox_state[0]: number of registered sandboxed cgroups. Fast-path gate so
 * the hooks cost one array lookup for every process on the host when no
 * sandbox is active. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sandbox_state SEC(".maps");

/* Registered sandbox targets: cgroup_id -> (profile_id << 32 | flags << 8 | mode). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);   /* cgroup id */
	__type(value, __u64); /* packed profile_id / flags / mode */
} sandbox_cgroups SEC(".maps");

/* Positive path policy: (profile_id << 32 | fnv32a(prefix)) -> access bitmask.
 * Prefixes are normalised (no trailing slash) on the Go side; the hooks check
 * the hash of every '/'-boundary prefix of the path plus the full path. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u8);
} sandbox_path_policy SEC(".maps");

/* Allowed egress CIDRs, scoped per profile. Key data starts with the 4-byte
 * big-endian profile id (always fully matched: prefixlen = 32 + cidr bits)
 * followed by the destination address. */
struct sbx_lpm_key_v4 {
	__u32 prefixlen;   /* 32 (profile) + 0-32 (cidr) */
	__u8  data[8];     /* profile_id BE + IPv4 address */
};

struct sbx_lpm_key_v6 {
	__u32 prefixlen;   /* 32 (profile) + 0-128 (cidr) */
	__u8  data[20];    /* profile_id BE + IPv6 address */
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct sbx_lpm_key_v4);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sandbox_net_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct sbx_lpm_key_v6);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sandbox_net_v6 SEC(".maps");

/* Allowed egress ports: (profile_id << 16 | port) -> 1. Consulted only when
 * the profile carries SBX_F_PORTS_FILTER. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} sandbox_ports SEC(".maps");

/* Hash-pinned exec allow-list, scoped per profile (issue #255, stitched with
 * #225's cosign exec allow-list). Key: {profile_id, sha256(binary)}. Value: the
 * fnv32a hash of the pinned path, so a digest is only honoured for the exact
 * path it was pinned to. Populated from userspace: statically from
 * allowed_exec_pins, or dynamically by the #225 verifier from cosign/Sigstore
 * attestations. The bprm_check hook consults it when the exec path is pinned;
 * the in-kernel binary-digest lookup itself is delivered by #225 (inode+ctime
 * cache), so today this map is the shared contract both features write to. */
struct sbx_exec_pin_key {
	__u32 profile_id;
	__u8  sha256[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sbx_exec_pin_key);
	__type(value, __u32); /* fnv32a(pinned path) */
} sandbox_exec_pins SEC(".maps");

/* Resolve the current task to a sandbox registration, walking cgroup
 * ancestors so that processes in child cgroups of a registered subtree
 * (e.g. containers inside a pod slice) are matched too.
 * Returns the packed sandbox_cgroups value, or 0 when not sandboxed. */
static __always_inline __u64 sandbox_lookup_current(void)
{
	__u32 zero = 0;
	__u64 *active = bpf_map_lookup_elem(&sandbox_state, &zero);
	if (!active || *active == 0)
		return 0;

	__u64 id = bpf_get_current_cgroup_id();
	__u64 *val = bpf_map_lookup_elem(&sandbox_cgroups, &id);
	if (val)
		return *val;

	int level;
	for (level = 1; level < SBX_MAX_CGROUP_LEVELS; level++) {
		__u64 aid = bpf_get_current_ancestor_cgroup_id(level);
		if (aid == 0 || aid == id)
			break; /* walked past the task's own level */
		val = bpf_map_lookup_elem(&sandbox_cgroups, &aid);
		if (val)
			return *val;
	}
	return 0;
}

/* Check an absolute path against the profile's positive policy.
 * Computes a rolling FNV-1a hash and consults sandbox_path_policy at every
 * '/' boundary plus the full path, so configured prefixes match any depth.
 * A SBX_DENY entry on any boundary wins over any allow.
 * Returns 1 when some boundary carries one of the `want` access bits. */
static __always_inline int sandbox_path_allowed(__u32 profile_id, const char *path, __u8 want)
{
	__u32 hash = 2166136261u; /* FNV offset basis */
	__u64 base = ((__u64)profile_id) << 32;
	int allowed = 0;
	int i;

	if (path[0] != '/')
		return 0; /* relative / unresolvable — deny-by-default */

	for (i = 0; i < PATH_HASH_MAX; i++) {
		char c = path[i];
		int boundary = (c == '\0') || (c == '/' && i > 0);
		if (boundary) {
			__u64 key = base | (__u64)hash;
			__u8 *ent = bpf_map_lookup_elem(&sandbox_path_policy, &key);
			if (ent) {
				if (*ent & SBX_DENY)
					return 0;
				if (*ent & want)
					allowed = 1;
			}
		}
		if (c == '\0')
			return allowed;
		hash ^= (__u32)(unsigned char)c;
		hash *= 16777619u; /* FNV prime */
	}
	return allowed;
}

/* Emit a sandbox violation audit event. profile_id travels in target_pid
 * (unused by these hooks); for socket_connect the destination is packed into
 * path[] as port(2, BE) + address bytes with sig = address family. */
static __always_inline void sandbox_emit(__u8 hook, __u8 action, __u32 profile_id,
					 const char *path_str, __u8 family,
					 const __u8 *addr, int addr_len, __u16 dport)
{
	struct lsm_audit_event *ae = bpf_ringbuf_reserve(&lsm_events,
				sizeof(struct lsm_audit_event), 0);
	if (!ae)
		return;

	ae->type         = EVENT_TYPE_LSM_AUDIT;
	ae->timestamp_ns = bpf_ktime_get_ns();
	ae->pid          = bpf_get_current_pid_tgid() >> 32;
	ae->uid          = (__u32)bpf_get_current_uid_gid();
	ae->target_pid   = profile_id;
	ae->action       = action;
	ae->hook         = hook;
	ae->sig          = family;
	bpf_get_current_comm(&ae->comm, sizeof(ae->comm));
	__builtin_memset(&ae->path, 0, sizeof(ae->path));
	if (path_str) {
		bpf_probe_read_kernel_str(&ae->path, sizeof(ae->path), path_str);
	} else if (addr && addr_len > 0 && addr_len <= 16) {
		ae->path[0] = (char)(dport >> 8);
		ae->path[1] = (char)(dport & 0xFF);
		bpf_probe_read_kernel(&ae->path[2], addr_len & 0x1F, addr);
	}
	bpf_ringbuf_submit(ae, 0);
}

/* Helper to check if PID is the agent itself */
static __always_inline bool is_agent_pid(__u32 pid)
{
	__u8 *val = bpf_map_lookup_elem(&lsm_agent_whitelist, &pid);
	return val != NULL && *val == 1;
}

/* Helper to check if PID is in blocklist */
static __always_inline bool is_blocked_pid(__u32 pid)
{
	__u8 *val = bpf_map_lookup_elem(&lsm_blocklist, &pid);
	return val != NULL && *val == 1;
}

/* Helper to update stats */
static __always_inline void update_stat(__u32 stat_idx)
{
	__u64 *count = bpf_map_lookup_elem(&lsm_stats, &stat_idx);
	if (count) {
		__sync_fetch_and_add(count, 1);
	}
}

/* FNV-1a 32-bit hash over a null-terminated string, max PATH_HASH_MAX bytes.
 * Must produce the same output as the Go fnv32a() in internal/collector/lsm.go.
 * Reference: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
 */
static __always_inline __u32 fnv32a(const char *str)
{
	__u32 hash = 2166136261u; /* FNV offset basis */
	int i;
	#pragma unroll
	for (i = 0; i < PATH_HASH_MAX; i++) {
		char c = str[i];
		if (c == '\0')
			break;
		hash ^= (__u32)(unsigned char)c;
		hash *= 16777619u; /* FNV prime */
	}
	return hash;
}

/* LSM hook: file_open — called before opening a file
 * 
 * Return 0 to allow, -EPERM to block
 * 
 * Performance note: Fast path (non-blocked PID) is a single map lookup
 * and should complete in < 100ns.
 */
SEC("lsm/bpf_file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Fast path: Agent itself is always allowed */
	if (is_agent_pid(pid)) {
		update_stat(LSM_STAT_FILE_OPEN_ALLOW);
		return 0;
	}

	/* Per-path blocklist check.  bpf_d_path() writes the full path into
	 * path_buf starting at index 0 (kernel moves the string to the front).
	 * If bpf_d_path() fails (e.g. anonymous/pipe file), skip the check and
	 * allow — we only block named-file paths.
	 */
	char path_buf[PATH_HASH_MAX] = {};
	if (bpf_d_path(&file->f_path, path_buf, sizeof(path_buf)) < 0) {
		update_stat(LSM_STAT_FILE_OPEN_ALLOW);
		return 0;
	}

	/* AI-agent sandbox: positive policy for sandboxed cgroups (issue #255).
	 * Runs before the blocklist — a sandboxed process is deny-by-default. */
	__u64 sbx = sandbox_lookup_current();
	if (sbx) {
		__u32 profile_id = (__u32)(sbx >> 32);
		__u8  mode       = (__u8)(sbx & 0xFF);
		__u32 fmode      = BPF_CORE_READ(file, f_mode);
		__u8  want;

		if (fmode & SBX_FMODE_EXEC)
			want = SBX_ALLOW_EXEC | SBX_ALLOW_READ;
		else if (fmode & SBX_FMODE_WRITE)
			want = SBX_ALLOW_WRITE;
		else
			want = SBX_ALLOW_READ;

		if (!sandbox_path_allowed(profile_id, path_buf, want)) {
			__u8 act = (mode == SANDBOX_MODE_ENFORCE) ?
				LSM_ACTION_SANDBOX_DENY : LSM_ACTION_SANDBOX_AUDIT;
			sandbox_emit(LSM_HOOK_FILE_OPEN, act, profile_id,
				     path_buf, 0, NULL, 0, 0);
			if (mode == SANDBOX_MODE_ENFORCE) {
				update_stat(LSM_STAT_FILE_OPEN_BLOCK);
				return -EACCES;
			}
		}
	}

	__u32 hash = fnv32a(path_buf);
	__u8 *blocked = bpf_map_lookup_elem(&path_blocklist, &hash);
	if (blocked && *blocked == 1) {
		update_stat(LSM_STAT_FILE_OPEN_BLOCK);

		/* Emit audit event for the blocked open */
		struct lsm_audit_event *ae = bpf_ringbuf_reserve(&lsm_events,
					sizeof(struct lsm_audit_event), 0);
		if (ae) {
			ae->type         = EVENT_TYPE_LSM_AUDIT;
			ae->timestamp_ns = bpf_ktime_get_ns();
			ae->pid          = pid;
			ae->uid          = (__u32)bpf_get_current_uid_gid();
			ae->target_pid   = 0;
			ae->action       = LSM_ACTION_DENY;
			ae->hook         = LSM_HOOK_FILE_OPEN;
			ae->sig          = 0;
			bpf_get_current_comm(&ae->comm, sizeof(ae->comm));
			bpf_probe_read_kernel_str(&ae->path, sizeof(ae->path), path_buf);
			bpf_ringbuf_submit(ae, 0);
		}
		return -EACCES;
	}

	update_stat(LSM_STAT_FILE_OPEN_ALLOW);
	return 0;
}

/* LSM hook: socket_connect — called before TCP connect
 *
 * Return 0 to allow, -EPERM to block
 */
SEC("lsm/bpf_socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *addr, int addrlen)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Fast path 1: Agent itself is always allowed */
	if (is_agent_pid(pid)) {
		update_stat(LSM_STAT_SOCK_CONN_ALLOW);
		return 0;
	}

	/* In-kernel IP/subnet/port blocklist — block before PID check so that
	 * any process (not just PID-blocked ones) is prevented from connecting
	 * to known-malicious destinations. */
	{
		__u16 sa_family = 0;
		int ip_blocked = 0;
		bpf_probe_read_kernel(&sa_family, sizeof(sa_family), &addr->sa_family);

		if (sa_family == AF_INET) {
			struct sockaddr_in sin = {};
			bpf_probe_read_kernel(&sin, sizeof(sin), addr);

			struct lpm_key_v4 blk = {};
			blk.prefixlen = 32;
			copy_ipv4_addr(blk.addr, sin.sin_addr.s_addr);
			if (bpf_map_lookup_elem(&net_block_ipv4, &blk))
				ip_blocked = 1;

			if (!ip_blocked) {
				__u16 dport = bpf_ntohs(sin.sin_port);
				if (bpf_map_lookup_elem(&net_block_ports, &dport))
					ip_blocked = 1;
			}
		} else if (sa_family == AF_INET6) {
			struct sockaddr_in6 sin6 = {};
			bpf_probe_read_kernel(&sin6, sizeof(sin6), addr);

			struct lpm_key_v6 blk = {};
			blk.prefixlen = 128;
			bpf_probe_read_kernel(blk.addr, 16, &sin6.sin6_addr);
			if (bpf_map_lookup_elem(&net_block_ipv6, &blk))
				ip_blocked = 1;

			if (!ip_blocked) {
				__u16 dport = bpf_ntohs(sin6.sin6_port);
				if (bpf_map_lookup_elem(&net_block_ports, &dport))
					ip_blocked = 1;
			}
		}

		if (ip_blocked) {
			update_stat(LSM_STAT_SOCK_CONN_BLOCK);
			record_net_drop();
			struct lsm_audit_event *ae = bpf_ringbuf_reserve(&lsm_events,
						sizeof(struct lsm_audit_event), 0);
			if (ae) {
				ae->type         = EVENT_TYPE_LSM_AUDIT;
				ae->timestamp_ns = bpf_ktime_get_ns();
				ae->pid          = pid;
				ae->uid          = (__u32)bpf_get_current_uid_gid();
				ae->target_pid   = 0;
				ae->action       = LSM_ACTION_DENY;
				ae->hook         = LSM_HOOK_SOCKET_CONNECT;
				ae->sig          = 0;
				bpf_get_current_comm(&ae->comm, sizeof(ae->comm));
				__builtin_memset(&ae->path, 0, sizeof(ae->path));
				bpf_ringbuf_submit(ae, 0);
			}
			return -EPERM;
		}
	}

	/* AI-agent sandbox: positive egress policy for sandboxed cgroups
	 * (issue #255). Loopback is always allowed so a sandboxed agent can
	 * reach local tooling (language servers, the ebpf-guard API) even
	 * under an empty CIDR list; everything else must match the profile's
	 * allowed_egress_cidrs (and ports, when the profile lists any). */
	__u64 sbx = sandbox_lookup_current();
	if (sbx) {
		__u32 profile_id = (__u32)(sbx >> 32);
		__u8  flags      = (__u8)((sbx >> 8) & 0xFF);
		__u8  mode       = (__u8)(sbx & 0xFF);
		__u16 sa_family  = 0;
		int   violation  = 0;
		__u8  addr_bytes[16] = {};
		int   addr_len   = 0;
		__u16 dport      = 0;

		bpf_probe_read_kernel(&sa_family, sizeof(sa_family), &addr->sa_family);

		if (sa_family == AF_INET) {
			struct sockaddr_in sin = {};
			bpf_probe_read_kernel(&sin, sizeof(sin), addr);
			dport = bpf_ntohs(sin.sin_port);
			copy_ipv4_addr(addr_bytes, sin.sin_addr.s_addr);
			addr_len = 4;

			if (addr_bytes[0] != 127) { /* loopback always allowed */
				struct sbx_lpm_key_v4 k = {};
				k.prefixlen = 32 + 32;
				k.data[0] = (__u8)(profile_id >> 24);
				k.data[1] = (__u8)(profile_id >> 16);
				k.data[2] = (__u8)(profile_id >> 8);
				k.data[3] = (__u8)profile_id;
				__builtin_memcpy(&k.data[4], addr_bytes, 4);
				if (!bpf_map_lookup_elem(&sandbox_net_v4, &k))
					violation = 1;
			}
		} else if (sa_family == AF_INET6) {
			struct sockaddr_in6 sin6 = {};
			bpf_probe_read_kernel(&sin6, sizeof(sin6), addr);
			dport = bpf_ntohs(sin6.sin6_port);
			bpf_probe_read_kernel(addr_bytes, 16, &sin6.sin6_addr);
			addr_len = 16;

			/* ::1 loopback always allowed */
			int is_loopback = 1;
			int i;
			#pragma unroll
			for (i = 0; i < 15; i++) {
				if (addr_bytes[i] != 0)
					is_loopback = 0;
			}
			if (addr_bytes[15] != 1)
				is_loopback = 0;

			if (!is_loopback) {
				struct sbx_lpm_key_v6 k = {};
				k.prefixlen = 32 + 128;
				k.data[0] = (__u8)(profile_id >> 24);
				k.data[1] = (__u8)(profile_id >> 16);
				k.data[2] = (__u8)(profile_id >> 8);
				k.data[3] = (__u8)profile_id;
				__builtin_memcpy(&k.data[4], addr_bytes, 16);
				if (!bpf_map_lookup_elem(&sandbox_net_v6, &k))
					violation = 1;
			}
		}

		if (!violation && addr_len > 0 && (flags & SBX_F_PORTS_FILTER)) {
			__u64 pkey = (((__u64)profile_id) << 16) | dport;
			if (!bpf_map_lookup_elem(&sandbox_ports, &pkey))
				violation = 1;
		}

		if (violation) {
			__u8 act = (mode == SANDBOX_MODE_ENFORCE) ?
				LSM_ACTION_SANDBOX_DENY : LSM_ACTION_SANDBOX_AUDIT;
			sandbox_emit(LSM_HOOK_SOCKET_CONNECT, act, profile_id,
				     NULL, (__u8)sa_family, addr_bytes, addr_len, dport);
			if (mode == SANDBOX_MODE_ENFORCE) {
				update_stat(LSM_STAT_SOCK_CONN_BLOCK);
				record_net_drop();
				return -EPERM;
			}
		}
	}

	/* Fast path 2: PID not in blocklist */
	if (!is_blocked_pid(pid)) {
		update_stat(LSM_STAT_SOCK_CONN_ALLOW);
		return 0;
	}

	/* Slow path: PID is blocked — emit audit event then deny */
	update_stat(LSM_STAT_SOCK_CONN_BLOCK);

	struct lsm_audit_event *ae = bpf_ringbuf_reserve(&lsm_events,
				sizeof(struct lsm_audit_event), 0);
	if (ae) {
		ae->type         = EVENT_TYPE_LSM_AUDIT;
		ae->timestamp_ns = bpf_ktime_get_ns();
		ae->pid          = pid;
		ae->uid          = (__u32)bpf_get_current_uid_gid();
		ae->target_pid   = 0;
		ae->action       = LSM_ACTION_DENY;
		ae->hook         = LSM_HOOK_SOCKET_CONNECT;
		ae->sig          = 0;
		bpf_get_current_comm(&ae->comm, sizeof(ae->comm));
		__builtin_memset(&ae->path, 0, sizeof(ae->path));
		bpf_ringbuf_submit(ae, 0);
	}
	return -EPERM;
}

/* LSM hook: task_kill — called before sending signal
 *
 * Return 0 to allow, -EPERM to block.
 *
 * Self-protection (issue #255, session 2, item 1): when the *sender* is inside
 * a sandboxed cgroup and the *target* is a protected ebpf-guard PID, the signal
 * is denied in enforce mode (audited in audit mode). This stops a contained
 * agent from killing the guard that constrains it. All other signalling is
 * audit-only (always allowed), preserving the prior behaviour.
 */
SEC("lsm/bpf_task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *target, struct kernel_siginfo *info,
	     int sig, const struct cred *cred)
{
	__u32 pid        = bpf_get_current_pid_tgid() >> 32;
	__u32 target_tgid = (__u32)BPF_CORE_READ(target, tgid);

	/* Self-protection: only relevant when a sandbox is active and the sender
	 * is inside it. Fast-path gate (one array lookup) short-circuits the host. */
	__u64 sbx = sandbox_lookup_current();
	if (sbx) {
		__u8 *prot = bpf_map_lookup_elem(&sandbox_protected_pids, &target_tgid);
		if (prot && *prot == 1 && target_tgid != pid) {
			__u8 mode = (__u8)(sbx & 0xFF);
			__u8 act = (mode == SANDBOX_MODE_ENFORCE) ?
				LSM_ACTION_SANDBOX_DENY : LSM_ACTION_SANDBOX_AUDIT;

			struct lsm_audit_event *dae = bpf_ringbuf_reserve(&lsm_events,
						sizeof(struct lsm_audit_event), 0);
			if (dae) {
				dae->type         = EVENT_TYPE_LSM_AUDIT;
				dae->timestamp_ns = bpf_ktime_get_ns();
				dae->pid          = pid;
				dae->uid          = (__u32)bpf_get_current_uid_gid();
				dae->target_pid   = target_tgid;
				dae->action       = act;
				dae->hook         = LSM_HOOK_TASK_KILL;
				dae->sig          = (__u8)sig;
				bpf_get_current_comm(&dae->comm, sizeof(dae->comm));
				__builtin_memset(&dae->path, 0, sizeof(dae->path));
				bpf_ringbuf_submit(dae, 0);
			}
			if (mode == SANDBOX_MODE_ENFORCE) {
				update_stat(LSM_STAT_TASK_KILL_BLOCK);
				return -EPERM;
			}
		}
	}

	/* Otherwise allow but emit an audit event recording who signalled whom */
	update_stat(LSM_STAT_TASK_KILL_ALLOW);

	struct lsm_audit_event *ae = bpf_ringbuf_reserve(&lsm_events,
				sizeof(struct lsm_audit_event), 0);
	if (ae) {
		ae->type         = EVENT_TYPE_LSM_AUDIT;
		ae->timestamp_ns = bpf_ktime_get_ns();
		ae->pid          = pid;
		ae->uid          = (__u32)bpf_get_current_uid_gid();
		ae->target_pid   = target_tgid;
		ae->action       = LSM_ACTION_AUDIT;
		ae->hook         = LSM_HOOK_TASK_KILL;
		ae->sig          = (__u8)sig;
		bpf_get_current_comm(&ae->comm, sizeof(ae->comm));
		__builtin_memset(&ae->path, 0, sizeof(ae->path));
		bpf_ringbuf_submit(ae, 0);
	}

	return 0;
}

/* LSM hook: bprm_check_security — called at the final stage of execve
 * before the new program image is committed (issue #255, sub-task 2).
 *
 * For sandboxed cgroups only: the exec path must fall under one of the
 * profile's allowed_exec prefixes. bprm->filename is the path being
 * executed as resolved by do_execve; a relative filename (execve of
 * "./x") cannot be prefix-matched and is treated as a violation —
 * deny-by-default. Non-sandboxed processes cost one array lookup.
 *
 * Shares the allowed-exec map mechanism intended for #225 (cosign exec
 * allowlist): the SBX_ALLOW_EXEC bit in sandbox_path_policy, plus the
 * sandbox_exec_pins hash allow-list for identity-pinned binaries.
 *
 * Caveats (documented in docs/ai-agent-sandbox.md):
 *   - Prefix/pin control binds the *binary*, not the script it runs: pinning
 *     /usr/bin/python3 still lets the agent run `python3 evil.py`. Constrain
 *     interpreters via file-read policy + egress, not exec alone.
 *   - Digest verification of the exec'd binary against sandbox_exec_pins is the
 *     #225 follow-up (inode+ctime cache); here we enforce the path allow-list.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
	__u64 sbx = sandbox_lookup_current();
	if (!sbx)
		return 0;

	__u32 profile_id = (__u32)(sbx >> 32);
	__u8  mode       = (__u8)(sbx & 0xFF);

	char path_buf[PATH_HASH_MAX] = {};
	const char *filename = BPF_CORE_READ(bprm, filename);
	if (filename)
		bpf_probe_read_kernel_str(path_buf, sizeof(path_buf), filename);

	if (!sandbox_path_allowed(profile_id, path_buf, SBX_ALLOW_EXEC)) {
		__u8 act = (mode == SANDBOX_MODE_ENFORCE) ?
			LSM_ACTION_SANDBOX_DENY : LSM_ACTION_SANDBOX_AUDIT;
		sandbox_emit(LSM_HOOK_BPRM_CHECK, act, profile_id,
			     path_buf, 0, NULL, 0, 0);
		if (mode == SANDBOX_MODE_ENFORCE)
			return -EPERM;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Escape-primitive containment (issue #255, session 2, item 3).
 *
 * A sandboxed AI agent has no legitimate need for the syscalls that break out
 * of a boundary: bpf() (tamper with the guard's own maps/links — item 2),
 * ptrace (inject into another process), mount (remap the filesystem view), and
 * kernel-module load (ring-0 code). Each hook is a no-op unless the caller is
 * inside a sandboxed cgroup; then it audits and, in enforce mode, denies. The
 * agent itself is never sandboxed, so its own bpf()/ptrace use is unaffected.
 * -------------------------------------------------------------------------
 */

/* Emit a bare sandbox-escape audit record (no path/addr payload). */
static __always_inline void sandbox_emit_escape(__u8 hook, __u8 action, __u32 profile_id)
{
	struct lsm_audit_event *ae = bpf_ringbuf_reserve(&lsm_events,
				sizeof(struct lsm_audit_event), 0);
	if (!ae)
		return;
	ae->type         = EVENT_TYPE_LSM_AUDIT;
	ae->timestamp_ns = bpf_ktime_get_ns();
	ae->pid          = bpf_get_current_pid_tgid() >> 32;
	ae->uid          = (__u32)bpf_get_current_uid_gid();
	ae->target_pid   = profile_id;
	ae->action       = action;
	ae->hook         = hook;
	ae->sig          = 0;
	bpf_get_current_comm(&ae->comm, sizeof(ae->comm));
	__builtin_memset(&ae->path, 0, sizeof(ae->path));
	bpf_ringbuf_submit(ae, 0);
}

/* Common gate: returns the packed sandbox value when the current task is
 * sandboxed AND, in enforce mode, records the block stat. Emits the audit
 * event regardless. Returns 1 to deny (enforce), 0 to allow. */
static __always_inline int sandbox_escape_decide(__u8 hook, __u32 block_stat)
{
	__u64 sbx = sandbox_lookup_current();
	if (!sbx)
		return 0;
	__u32 profile_id = (__u32)(sbx >> 32);
	__u8  mode       = (__u8)(sbx & 0xFF);
	__u8  act = (mode == SANDBOX_MODE_ENFORCE) ?
		LSM_ACTION_SANDBOX_DENY : LSM_ACTION_SANDBOX_AUDIT;
	sandbox_emit_escape(hook, act, profile_id);
	if (mode == SANDBOX_MODE_ENFORCE) {
		update_stat(block_stat);
		return 1;
	}
	return 0;
}

/* LSM hook: bpf — gates the bpf() syscall. Denying it for a sandboxed task is
 * also the kernel-side lock on self-protection (item 2): a contained process
 * cannot BPF_PROG_DETACH our LSM links or BPF_MAP_UPDATE/DELETE the sandbox_*
 * maps that constrain it. */
SEC("lsm/bpf")
int BPF_PROG(lsm_sandbox_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	if (sandbox_escape_decide(LSM_HOOK_BPF, LSM_STAT_SBX_BPF_BLOCK))
		return -EPERM;
	return 0;
}

/* LSM hook: ptrace_access_check — a sandboxed task attaching to / inspecting
 * another process (PTRACE_ATTACH, PTRACE_SEIZE, process_vm_readv, ...). */
SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_sandbox_ptrace, struct task_struct *child, unsigned int mode)
{
	if (sandbox_escape_decide(LSM_HOOK_PTRACE, LSM_STAT_SBX_PTRACE_BLOCK))
		return -EPERM;
	return 0;
}

/* LSM hook: sb_mount — a sandboxed task calling mount(2) to remap its
 * filesystem view (bind mounts, procfs remounts, overlay escapes). */
SEC("lsm/sb_mount")
int BPF_PROG(lsm_sandbox_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data)
{
	if (sandbox_escape_decide(LSM_HOOK_MOUNT, LSM_STAT_SBX_MOUNT_BLOCK))
		return -EPERM;
	return 0;
}

/* -------------------------------------------------------------------------
 * Sprint 33.0: Kernel Module Load Detection
 * -------------------------------------------------------------------------
 *
 * LSM hook: kernel_module_request
 * Called when the kernel requests automatic module loading (e.g., modprobe).
 * We emit an event and always return 0 (audit-only; policy enforced in Go).
 */
SEC("lsm/kernel_module_request")
int BPF_PROG(lsm_kernel_module_request, char *kmod_name)
{
	struct kmod_event *e;

	/* Escape-primitive containment: a sandboxed task triggering a module
	 * load is denied in enforce mode (issue #255, session 2, item 3). */
	if (sandbox_escape_decide(LSM_HOOK_MODULE, LSM_STAT_SBX_MODULE_BLOCK))
		return -EPERM;

	update_stat(LSM_STAT_KMOD_LOAD);

	e = bpf_ringbuf_reserve(&lsm_events, sizeof(struct kmod_event), 0);
	if (!e)
		return 0;

	e->type      = EVENT_TYPE_KMOD_LOAD;
	e->timestamp = bpf_ktime_get_ns();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)(pid_tgid >> 32);
	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = (__u32)uid_gid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Fill parent info */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = task->real_parent;
	if (parent) {
		e->ppid = parent->tgid;
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm), &parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}

	/* Copy module name (kernel-provided pointer) */
	if (kmod_name)
		bpf_probe_read_kernel_str(&e->mod_name, sizeof(e->mod_name), kmod_name);
	else
		__builtin_memset(&e->mod_name, 0, sizeof(e->mod_name));

	e->from_tmpfs = 0; /* not path-based; kernel_read_file hook handles path check */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * LSM hook: kernel_read_file
 * Called when the kernel reads a file for interpretation (modules, firmware, etc.).
 * We emit an event only when id == READING_MODULE.
 *
 * kernel_read_file_id enum: READING_UNKNOWN=0, READING_FIRMWARE=1,
 * READING_MODULE=2, READING_KEXEC_IMAGE=3, READING_KEXEC_INITRAMFS=4,
 * READING_POLICY=5, READING_X509_CERTIFICATE=6.
 */
#define READING_MODULE 2

SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	if (id != READING_MODULE)
		return 0;

	update_stat(LSM_STAT_KMOD_LOAD);

	struct kmod_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(struct kmod_event), 0);
	if (!e)
		return 0;

	e->type      = EVENT_TYPE_KMOD_LOAD;
	e->timestamp = bpf_ktime_get_ns();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)(pid_tgid >> 32);
	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = (__u32)uid_gid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = task->real_parent;
	if (parent) {
		e->ppid = parent->tgid;
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm), &parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}

	/* Read file path into mod_name via dentry */
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if (dentry)
		bpf_probe_read_kernel_str(&e->mod_name, sizeof(e->mod_name),
					  BPF_CORE_READ(dentry, d_name.name));
	else
		__builtin_memset(&e->mod_name, 0, sizeof(e->mod_name));

	/* Check if path starts with /tmp or /dev/shm (suspicious load location) */
	e->from_tmpfs = 0;
	if (e->mod_name[0] == '/' &&
	    ((e->mod_name[1] == 't' && e->mod_name[2] == 'm' && e->mod_name[3] == 'p') ||
	     (e->mod_name[1] == 'd' && e->mod_name[2] == 'e' && e->mod_name[3] == 'v')))
		e->from_tmpfs = 1;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* -------------------------------------------------------------------------
 * Sprint 33.0: exec-time cgroup recording (used by cgroup.bpf.c)
 * Record the initial cgroup ID of each process at exec time so that
 * cgroup_attach_task can detect migration out of the container's cgroup tree.
 * -------------------------------------------------------------------------
 */
SEC("tp/sched/sched_process_exec")
int trace_exec_record_cgroup(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	bpf_map_update_elem(&pid_initial_cgroup, &pid, &cgroup_id, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
