/*
 * common.h - Shared structures between eBPF programs and Go userspace.
 * Target: Linux kernel 5.15+ with BTF/CO-RE support.
 */

#ifndef __EBPF_GUARD_COMMON_H
#define __EBPF_GUARD_COMMON_H

/* vmlinux.h provides all kernel type definitions for CO-RE compilation.
 * Files that already include vmlinux.h directly (lsm.bpf.c, cgroup.bpf.c)
 * will hit the include guard below and skip this inclusion. */
#ifndef __VMLINUX_H__
#include "vmlinux.h"
#define __VMLINUX_H__
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Kernel address-space annotation — not available in BPF context */
#ifndef __user
#define __user
#endif

/* errno values used in BPF programs */
#ifndef E2BIG
#define E2BIG 7
#endif

/* Event type identifiers - must match pkg/types/event.go */
#define EVENT_TYPE_SYSCALL     1
#define EVENT_TYPE_TCP_CONNECT 2
#define EVENT_TYPE_FILE_ACCESS 3
#define EVENT_TYPE_TLS         4
#define EVENT_TYPE_DNS         5
#define EVENT_TYPE_PRIVESC     6  /* Privilege escalation: capability change */
#define EVENT_TYPE_NET_CLOSE   7  /* TCP connection closed with duration */
#define EVENT_TYPE_KMOD_LOAD   8  /* Kernel module load (insmod/init_module) */
#define EVENT_TYPE_CGROUP_ESC  9  /* Process migrated to different cgroup namespace */
#define EVENT_TYPE_GPU        10  /* CUDA/GPU memory operation (DtoH/HtoD/alloc/free) */
#define EVENT_TYPE_LSM_AUDIT  11  /* LSM hook audit record (deny or audit-only action) */
#define EVENT_TYPE_IO_URING   14  /* io_uring activity (setup/enter) */
#define EVENT_TYPE_BPF_PROGRAM 15 /* bpf() syscall: BPF_PROG_LOAD / BPF_MAP_CREATE */

/* LSM hook identifiers — match struct lsm_audit_event.hook */
#define LSM_HOOK_FILE_OPEN       0
#define LSM_HOOK_SOCKET_CONNECT  1
#define LSM_HOOK_TASK_KILL       2

/* LSM audit action codes — match struct lsm_audit_event.action */
#define LSM_ACTION_AUDIT  0  /* event allowed, audit-only */
#define LSM_ACTION_DENY   1  /* event blocked (-EACCES/-EPERM) */

/* File operation codes - must match pkg/types/event.go */
#define FILE_OP_OPEN  0
#define FILE_OP_READ  1
#define FILE_OP_WRITE 2
/*
 * FILE_OP_CHMOD — волна 6.2.1, слой 3 (находка №220).
 *
 * До неё chmod был виден агенту ТОЛЬКО как номер сисколла (90/91/268) на
 * event_type: syscall, где аргументы — сырые указатели, а не разрешённые
 * строки. Три правила (evasion_chmod_sensitive, sigma_chmod_executable_tmp,
 * sigma_sensitive_file_chmod) поэтому не проверяли путь ни одно, их имена
 * обещали "/bin", "/tmp" и "sensitive file", а условие у всех трёх было одно
 * и то же — «случился chmod». Это давало три алерта на каждый chmod любого
 * файла: 144 из 1787 алертов окна замера 6.2, крупнейший одиночный кластер.
 *
 * Сужать их исключениями было нечем и незачем: правилу, которое не знает
 * пути, любой префиксный предикат даёт «поле пусто → не совпало», то есть
 * тихую смерть — ровно тот дефект, который волна ловит у других. Поэтому
 * chmod заводится там, где путь уже разрешается: в файловом коллекторе, у
 * которого для chmod(2)/fchmodat(2) есть указатель на строку в user space, а
 * для fchmod(2) — своя же таблица fd→путь (fd_path_map).
 */
#define FILE_OP_CHMOD 3

/* Address family codes - must match pkg/types/event.go */
#define AF_INET   2
#define AF_INET6  10

/* Maximum lengths for string fields */
#define COMM_LEN      16
#define FILENAME_LEN  256
#define KMOD_NAME_LEN 64   /* MODULE_NAME_LEN from kernel is 56; use 64 for alignment */
#define PROC_ARGS_MAX 512  /* Max bytes stored for process cmdline args */

/*
 * struct event - Unified event structure sent from kernel to userspace.
 * Layout must match exactly with Go struct Event in pkg/types/event.go
 */
struct event {
	__u32 type;
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;		/* Parent process ID */
	__u32 uid;
	__u8  comm[COMM_LEN];
	__u8  parent_comm[COMM_LEN];	/* Parent process name (if available) */
	/* Union-style payload - only one field is valid based on type */
	union {
		struct {
			__s64 nr;
			__s64 ret;
			__u64 args[6];
		} syscall;
		struct {
			__u8  saddr[16];	/* Source IP: IPv4 in first 4 bytes, IPv6 uses all 16 */
			__u8  daddr[16];	/* Dest IP: IPv4 in first 4 bytes, IPv6 uses all 16 */
			__u16 sport;
			__u16 dport;
			__u8  proto;
			__u8  family;		/* AF_INET (2) or AF_INET6 (10) */
		} network;
		struct {
			__u8  filename[FILENAME_LEN];
			__s32 flags;
			__u32 mode;
			__u8  op;
			__u8  fd_path_truncated; /* 1 if filename was truncated at 256 bytes */
		} file;
	};
} __attribute__((packed));

/*
 * struct kmod_event - Sent when a kernel module is loaded.
 * Emitted by lsm/kernel_module_request and lsm/kernel_read_file hooks.
 */
struct kmod_event {
	__u32 type;           /* EVENT_TYPE_KMOD_LOAD */
	__u64 timestamp;
	__u32 pid;
	__u32 uid;
	__u8  comm[COMM_LEN];
	__u8  parent_comm[COMM_LEN];
	__u32 ppid;
	__u8  mod_name[KMOD_NAME_LEN]; /* module name or path */
	__u8  from_tmpfs;              /* 1 if path is in /tmp or /dev/shm */
} __attribute__((packed));

/*
 * struct cgroup_escape_event - Sent when a process migrates to a different
 * cgroup namespace than its recorded-at-exec initial cgroup.
 */
struct cgroup_escape_event {
	__u32 type;           /* EVENT_TYPE_CGROUP_ESC */
	__u64 timestamp;
	__u32 pid;
	__u32 uid;
	__u8  comm[COMM_LEN];
	__u8  parent_comm[COMM_LEN];
	__u32 ppid;
	__u64 init_cgroup_id; /* cgroup id recorded at exec */
	__u64 new_cgroup_id;  /* cgroup id at migration time */
} __attribute__((packed));

/*
 * struct lsm_audit_event - emitted by LSM hooks on enforcement / audit actions.
 * type == EVENT_TYPE_LSM_AUDIT (11).  Sent via the lsm_events ring buffer.
 * Emitted on every file_open block, socket_connect block, and task_kill.
 */
struct lsm_audit_event {
	__u32 type;           /* EVENT_TYPE_LSM_AUDIT */
	__u64 timestamp_ns;
	__u32 pid;
	__u32 target_pid;     /* signal target PID (task_kill only, 0 otherwise) */
	__u32 uid;
	__u8  action;         /* LSM_ACTION_AUDIT or LSM_ACTION_DENY */
	__u8  hook;           /* LSM_HOOK_FILE_OPEN / _SOCKET_CONNECT / _TASK_KILL */
	__u8  sig;            /* signal number (task_kill only, 0 otherwise) */
	char  comm[16];
	char  path[64];       /* file path (file_open only, NUL-terminated) */
} __attribute__((packed));

/*
 * struct proc_args - cached process command-line arguments.
 * Populated by the sched_process_exec tracepoint hook in syscall.bpf.c.
 * Keyed by TGID in proc_args_map; consumed by userspace collectors when
 * enriching file, network, and syscall events with proc.args.
 */
struct proc_args {
	/* exec_ts - bpf_ktime_get_ns() at the sched_process_exec that wrote this
	 * entry (6.0j/№210). It is the discriminator userspace uses to tell the
	 * sys_enter record of an execve from its sys_exit record: the entry is
	 * written between the two, so exec_ts < event.timestamp holds on the
	 * exit record and not on the enter record of the same execve. Before
	 * this field the discriminator was comm vs basename(argv[0]), which a
	 * spoofed argv[0] (execve with argv[0] != path, T1036.003) and every
	 * login shell (argv[0] = "-bash") defeat, blanking proc.args and
	 * silencing the whole class of rules predicated on it.
	 *
	 * First field, not appended: __u64 needs 8-byte alignment, and after
	 * args[512] + truncated + _pad[3] it would sit at offset 516 and cost
	 * four more bytes of tail padding. */
	__u64 exec_ts;
	char args[PROC_ARGS_MAX]; /* Space-separated argv, NUL-terminated */
	__u8 truncated;           /* 1 when original cmdline exceeded PROC_ARGS_MAX */
	__u8 _pad[3];
};

/*
 * proc_args_map - LRU hash of per-TGID process cmdline arguments.
 * Written on sched_process_exec; read by userspace collector goroutines.
 * LRU eviction keeps memory bounded without explicit cleanup.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);                /* TGID */
	__type(value, struct proc_args);
} proc_args_map SEC(".maps");

/* Sampling configuration - configurable per event type */
struct sampling_config {
	__u32 syscall_rate;   /* Sample 1 in N syscall events (0 = disable, 1 = all) */
	__u32 network_rate;   /* Sample 1 in N network events (0 = disable, 1 = all) */
	__u32 file_rate;      /* Sample 1 in N file events (0 = disable, 1 = all) */
	__u32 enabled;        /* Global sampling enable flag */
};

/* Sampling config map - writable from userspace */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sampling_config);
} sampling_config SEC(".maps");

/*
 * comm_filter_map - per-comm allowlist/denylist.
 * key: comm string (up to 16 bytes, NUL-padded), value: 1 = pass, 0 = drop.
 * When a comm is present with value 0, all events from that process are
 * discarded in the kernel before reaching the ring buffer.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[COMM_LEN]);
	__type(value, __u8);
} comm_filter_map SEC(".maps");

/*
 * syscall_filter_map - per-syscall-number monitoring switch.
 * key: syscall number (__u32), value: 1 = monitor, 0 = ignore.
 * When enabled and a syscall number is absent or set to 0, the event is
 * discarded before reaching the ring buffer.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, __u8);
} syscall_filter_map SEC(".maps");

/*
 * kernel_filter_config - global on/off switch for content-based filtering.
 * key 0: enabled flag (__u8, 1 = active).
 * Allows runtime toggling without reloading BPF programs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} kernel_filter_config SEC(".maps");

/*
 * agent_pid_map - stores the PID of the ebpf-guard agent itself.
 * Events from this PID are filtered out in the kernel (self-exclusion).
 * key 0: agent PID (__u32)
 * This allows the agent to filter out its own I/O operations (SQLite,
 * audit.jsonl, API responses) without affecting visibility into attacks
 * on agent files by other processes.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} agent_pid_map SEC(".maps");

/* Per-CPU event counters for sampling */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3); /* 0=syscall, 1=network, 2=file */
	__type(key, __u32);
	__type(value, __u64);
} event_counters SEC(".maps");

/*
 * map_full_counters - per-CPU counters incremented when a BPF map insert fails
 * because the map is at capacity.  Indexed by map ID:
 *   0 = syscall_args   1 = conn_start_map   2 = conn_meta_map
 * Userspace drains these counters and exports them as
 * ebpf_guard_bpf_map_full_total{map_name}.
 */
#define MAP_FULL_IDX_SYSCALL_ARGS  0
#define MAP_FULL_IDX_CONN_START    1
#define MAP_FULL_IDX_CONN_META     2
#define MAP_FULL_IDX_COUNT         3

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAP_FULL_IDX_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} map_full_counters SEC(".maps");

/*
 * record_map_full - increment the per-CPU map-full counter for map_idx.
 * Call this whenever bpf_map_update_elem returns -E2BIG or -ENOMEM,
 * indicating that a bounded map is at capacity and the insert was dropped.
 */
static __always_inline void record_map_full(__u32 map_idx)
{
	__u64 *cnt = bpf_map_lookup_elem(&map_full_counters, &map_idx);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

/* BPF map definitions using BTF-enabled maps (kernel 5.15+) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); /* 4MB ring buffer */
} events SEC(".maps");

/* Helper: check if event should be sampled based on rate */
static __always_inline bool should_sample(__u32 event_type, __u32 rate)
{
	struct sampling_config *cfg;
	__u32 key = 0;
	__u32 counter_key;
	__u64 *counter;
	__u64 new_count;

	/* Get sampling config */
	cfg = bpf_map_lookup_elem(&sampling_config, &key);
	if (!cfg || !cfg->enabled)
		return true; /* No sampling config, emit all events */

	/* Map event type to counter index */
	switch (event_type) {
	case EVENT_TYPE_SYSCALL:
		counter_key = 0;
		if (rate == 0) rate = cfg->syscall_rate;
		break;
	case EVENT_TYPE_TCP_CONNECT:
		counter_key = 1;
		if (rate == 0) rate = cfg->network_rate;
		break;
	case EVENT_TYPE_FILE_ACCESS:
		counter_key = 2;
		if (rate == 0) rate = cfg->file_rate;
		break;
	default:
		return true;
	}

	/* Rate of 0 means disabled, rate of 1 means all events */
	if (rate == 0)
		return false; /* Drop all events of this type */
	if (rate == 1)
		return true;  /* Emit all events */

	/* Increment counter and check if we should sample */
	counter = bpf_map_lookup_elem(&event_counters, &counter_key);
	if (counter) {
		new_count = __sync_fetch_and_add(counter, 1);
	} else {
		new_count = 0;
	}

	/* Sample 1 in 'rate' events */
	return (new_count % rate) == 0;
}

/*
 * ringbuf_full_counters - per-CPU counter for a failed bpf_ringbuf_reserve()
 * on the shared `events` ring buffer (syscall.bpf.c, network.bpf.c,
 * fileaccess.bpf.c, privesc.bpf.c all include this header and share this
 * counter within their own compiled object). Index 0: total reserve
 * failures, i.e. events the kernel produced but the ring buffer was too full
 * to accept.
 *
 * This is placed inside reserve_event()/reserve_event_with_sampling() below,
 * not at the call sites — 5.9.6a (№71). The project already tried "count at
 * every call site" for a different drop class and it held for a while
 * (path_filter_drop_counters, net_block_counters), but there are more than
 * twenty bpf_ringbuf_reserve() call sites across the whole tree, and a drop
 * counted only by caller discipline is a drop that goes uncounted the first
 * time someone adds call site twenty-one and forgets. Counting inside the
 * macro means the number of call sites is irrelevant.
 *
 * A should_sample()==false skip is NOT a ring-buffer-full drop — it is a
 * deliberate sampling decision, already accounted for by event_counters —
 * and must not increment this counter. The macro below only reaches the
 * increment after actually calling bpf_ringbuf_reserve() and finding it
 * returned NULL, so a sampled-out event never touches this counter.
 *
 * Userspace sums across CPUs and exports as
 * ebpf_guard_events_dropped_total{collector=...,reason="ringbuf_full"} —
 * see cmd/ebpf-guard/main.go's ringbufFullRegistry — and separately backs
 * ebpf_guard_bpf_lost_events_total{collector=...} for these four collectors
 * (watchdog.DropTracker), replacing the previous userspace-hop count that
 * metric used to report under a kernel-sounding name (№71 in plan.md).
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_full_counters SEC(".maps");

/* Increment the in-kernel ring-buffer-full drop counter (per-CPU). */
static __always_inline void record_ringbuf_full(void)
{
	__u32 idx = 0;
	__u64 *cnt = bpf_map_lookup_elem(&ringbuf_full_counters, &idx);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

/*
 * events_emitted_counters - per-CPU counter for a SUCCESSFUL
 * bpf_ringbuf_reserve() on the shared `events` ring buffer — the left-hand
 * side of 5.9.6b's (№72) event balance identity:
 *   emitted_kernel == events_total + Σdropped + excluded + malformed
 * Without this, "how many events did the kernel actually produce" has to be
 * inferred from events_total, which is measured downstream of every filter —
 * exactly the gap 5.9.6b closes.
 *
 * A reservation that succeeds here always reaches submit_event() in this
 * codebase's four shared-ringbuf files (syscall/network/fileaccess/privesc
 * never call bpf_ringbuf_discard() on the `events` ring buffer), so counting
 * at reserve success is equivalent to counting at submit and is simpler:
 * one place instead of eight call sites.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} events_emitted_counters SEC(".maps");

/* Increment the in-kernel successful-reserve counter (per-CPU). */
static __always_inline void record_event_emitted(void)
{
	__u32 idx = 0;
	__u64 *cnt = bpf_map_lookup_elem(&events_emitted_counters, &idx);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

/* Helper macro to reserve space in ring buffer with sampling check */
#define reserve_event_with_sampling(event_type, sample_rate) \
	({ \
		struct event *__e = NULL; \
		if (should_sample(event_type, sample_rate)) { \
			__e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0); \
			if (__e) \
				record_event_emitted(); \
			else \
				record_ringbuf_full(); \
		} \
		__e; \
	})

/* Helper macro to reserve space in ring buffer (no sampling - legacy) */
#define reserve_event() \
	({ \
		struct event *__e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0); \
		if (__e) \
			record_event_emitted(); \
		else \
			record_ringbuf_full(); \
		__e; \
	})

/* Helper macro to submit event to ring buffer */
#define submit_event(e) \
	bpf_ringbuf_submit(e, 0)

/*
 * kernel_filter_enabled - returns true when content-based BPF filtering is on.
 */
static __always_inline bool kernel_filter_enabled(void)
{
	__u32 key = 0;
	__u8 *val = bpf_map_lookup_elem(&kernel_filter_config, &key);
	return val && *val;
}

/*
 * comm_is_denied - returns true if the current task's comm is in the denylist
 * (present in comm_filter_map with value 0).  Returns false when the comm is
 * not in the map (pass through) or is explicitly whitelisted (value 1).
 */
static __always_inline bool comm_is_denied(void)
{
	char comm[COMM_LEN] = {};
	__u8 *val;

	bpf_get_current_comm(comm, sizeof(comm));
	val = bpf_map_lookup_elem(&comm_filter_map, comm);
	/* val == NULL  → not in map → pass; val != NULL && *val == 0 → deny */
	return val && (*val == 0);
}

/*
 * syscall_is_monitored - returns true if syscall number nr should be
 * forwarded.  Returns true when the syscall_filter_map entry is 1, false
 * when it is 0 or absent (absent means "not in the monitored set").
 */
static __always_inline bool syscall_is_monitored(__s64 nr)
{
	__u32 key;
	__u8 *val;

	if (nr < 0 || nr >= 512)
		return false;

	key = (__u32)nr;
	val = bpf_map_lookup_elem(&syscall_filter_map, &key);
	return val && (*val == 1);
}

/*
 * pid_is_agent - returns true if the current process is the ebpf-guard agent.
 * This is used for self-exclusion: the agent's own I/O operations (SQLite,
 * audit.jsonl, API responses) are filtered out in the kernel, but attacks
 * on agent files by other processes remain visible.
 *
 * The check is on the TGID (thread-group leader), so every thread of the agent
 * is covered, and it is by PID rather than by path — a different process
 * touching the agent's own files still produces events, which is what keeps
 * "attack on the agent" detectable.
 *
 * agent_pid_map is a BPF_MAP_TYPE_ARRAY, so the lookup always succeeds and
 * yields 0 until userspace sets the real PID. Zero is therefore treated as
 * "self-exclusion not configured": without this guard, every program on the
 * host would be compared against 0 during the window between BPF load and
 * SetAgentPID, and any event whose TGID read as 0 would be dropped silently.
 */
static __always_inline bool pid_is_agent(void)
{
	__u32 key = 0;
	__u32 *agent_pid;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	agent_pid = bpf_map_lookup_elem(&agent_pid_map, &key);
	if (!agent_pid || *agent_pid == 0)
		return false;

	return tgid == *agent_pid;
}

/*
 * Observer-tree exclusion (находка №34 / 5.9.2g) — in-kernel version.
 *
 * WHY THIS IS IN THE KERNEL AND NOT IN USERSPACE.
 * 5.9a implemented this filter in the correlator: every event walked the
 * lineage tracker, and on a cache miss bootstrapped the ancestor chain from
 * /proc. That is one map lookup plus, on the miss path, several syscalls and
 * allocations — per event, on the hottest path in the agent, to decide that
 * the event should be thrown away. It also filtered too late to help: the
 * event had already crossed the ring buffer, the router and the per-shard
 * buffer before anything looked at its ancestry. Here it costs one LRU hash
 * lookup, and on a miss a bounded parent walk, before bpf_ringbuf_reserve.
 *
 * WHY A PARENT WALK AND NOT A sched_process_fork HOOK.
 * The originally planned fix (5.9.1a) propagated membership at fork time.
 * A walk is strictly better here for three reasons: it needs no fork hook and
 * no exit hook (so no PID-lifetime bookkeeping and no leak when a process
 * dies without one), it works for processes that already existed when the
 * root PID was set (a fork hook only ever sees the future), and — the reason
 * that actually matters — each BPF object built from this header keeps its
 * OWN copy of every map, so a fork hook living in one object could never
 * populate the maps consulted by the others. The walk derives membership from
 * task_struct, which all objects can read.
 *
 * SEMANTICS. Returns true when the current task's tgid is the observer root
 * or has it among its ancestors, walking real_parent up to OBSERVER_MAX_DEPTH
 * hops or until init (tgid 1) / a NULL parent. Both outcomes are memoised in
 * an LRU hash, so a long-lived harness child pays the walk once. Root 0 means
 * "not configured" and short-circuits to false — same convention as
 * agent_pid_map, and for the same reason: without it every process on the
 * host would be compared against 0 in the window between BPF load and the
 * first SetObserverRoot.
 *
 * TEST-ONLY. Userspace never sets a non-zero root unless
 * correlator.observer_exclude.enabled is on (config-test.yaml). On a
 * production deployment this is one array lookup returning 0.
 */
#define OBSERVER_MAX_DEPTH 12

/* observer_root_pid — key 0 holds the harness root TGID, 0 = not configured. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} observer_root_pid SEC(".maps");

/*
 * observer_tree_cache — memoised membership, keyed by TGID.
 *
 * The value carries the root the verdict was decided under, not just the
 * verdict. Каждый прогон харнесса — новый root PID, and a bare boolean would
 * outlive the root that produced it: a PID cached as "in the tree" under the
 * previous run would stay excluded under the next one (silently invisible to
 * correlation), and a PID cached as "not in the tree" would stay visible even
 * after becoming a descendant of the new root. The userspace filter had to
 * flush its whole memo in SetObserverRoot for exactly this reason; tagging the
 * entry makes a stale verdict simply not match, so there is nothing to flush
 * and no window in which the two sides disagree.
 *
 * LRU eviction is what makes PID reuse tolerable: a recycled PID inherits a
 * stale verdict only while the entry survives, and is re-decided by the walk as
 * soon as it is evicted. A non-LRU hash would instead fill up and start
 * refusing inserts, silently turning the memo off under fork pressure — the
 * failure mode is "slow", not "wrong", but it would be invisible either way.
 */
struct observer_verdict {
	__u32 root;   /* the observer root this verdict was decided under */
	__u8  member; /* 1 = in the observer tree, 0 = walked and not in it */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct observer_verdict);
} observer_tree_cache SEC(".maps");

/*
 * observer_excluded_counters — per-CPU count of events dropped as belonging to
 * the measurement harness. Userspace sums across CPUs and exports the delta as
 * ebpf_guard_events_excluded_total{reason="observer_tree"}, the same series
 * 5.9a published from the correlator. Without it this filter would be exactly
 * the silent blindness the wave exists to eliminate: event volume drops and
 * nothing says why.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} observer_excluded_counters SEC(".maps");

static __always_inline void record_observer_excluded(void)
{
	__u32 idx = 0;
	__u64 *cnt = bpf_map_lookup_elem(&observer_excluded_counters, &idx);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

/*
 * pid_is_observer - true if the current task belongs to the measurement
 * harness's process tree.
 *
 * The loop is #pragma unroll'd over a compile-time bound so the verifier sees
 * a fixed instruction count rather than a loop it has to prove terminates —
 * kernel 5.15 accepts bounded loops, but unrolling keeps this working on the
 * older verifiers the project still targets, and OBSERVER_MAX_DEPTH is small
 * enough that the unrolled form stays cheap.
 *
 * Note on the read style: this walks real_parent (the true parent), not
 * parent, so a process reparented by ptrace does not appear to leave the
 * harness tree. Reads go through BPF_CORE_READ so the offsets are relocated
 * by BTF rather than baked in — see cgroup.bpf.c for the same pattern.
 */
static __always_inline bool pid_is_observer(void)
{
	__u32 key = 0;
	__u32 *root_ptr;
	__u32 root;
	__u32 tgid;
	struct observer_verdict *cached;
	struct observer_verdict verdict = {};
	struct task_struct *task;
	int i;

	root_ptr = bpf_map_lookup_elem(&observer_root_pid, &key);
	if (!root_ptr)
		return false;
	/* Read the root once into a local: it is re-checked on every hop below,
	 * and userspace can rewrite the map mid-walk when the harness restarts.
	 * Re-reading through the pointer would let one walk compare its first
	 * hops against one root and its last hops against another, producing a
	 * verdict that was never true of either. */
	root = *root_ptr;
	if (root == 0)
		return false;

	tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (tgid == root)
		return true;

	cached = bpf_map_lookup_elem(&observer_tree_cache, &tgid);
	if (cached && cached->root == root)
		return cached->member == 1;

	task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return false;

	verdict.root = root;

#pragma unroll
	for (i = 0; i < OBSERVER_MAX_DEPTH; i++) {
		struct task_struct *parent = BPF_CORE_READ(task, real_parent);
		__u32 ptgid;

		if (!parent)
			break;
		ptgid = BPF_CORE_READ(parent, tgid);
		/* The root test comes first. If the harness root ever were PID 1
		 * itself, testing for init before testing for the root would break
		 * out of the walk one hop before the match and report every process
		 * on the host as unrelated. */
		if (ptgid == root) {
			verdict.member = 1;
			break;
		}
		/* Reaching init (1) or a zero tgid means the chain ended without the
		 * root: stop rather than spend the remaining hops walking above init,
		 * where the answer can no longer change. */
		if (ptgid == 0 || ptgid == 1)
			break;
		task = parent;
	}

	/* Both verdicts are cached. Caching only the positive one would leave
	 * every unrelated process on the host repeating the full walk on every
	 * event — the negative answer is the common case and the expensive one. */
	bpf_map_update_elem(&observer_tree_cache, &tgid, &verdict, BPF_ANY);
	return verdict.member == 1;
}

/*
 * observer_should_drop - pid_is_observer() plus the drop counter, so call
 * sites read as one line and cannot accidentally drop without counting.
 */
static __always_inline bool observer_should_drop(void)
{
	if (!pid_is_observer())
		return false;
	record_observer_excluded();
	return true;
}

/*
 * Network blocklist maps — in-kernel IP/subnet/port blocking.
 *
 * net_block_ipv4 / net_block_ipv6: LPM TRIE for IPv4/IPv6 subnets.
 * Lookup key: { prefixlen = 32/128 (full host bits), addr = destination IP }.
 * The trie performs longest-prefix-match: subnets are inserted with their
 * prefix length; individual host lookups use prefixlen = 32/128.
 *
 * net_block_ports: HASH of destination TCP ports in host byte order.
 *
 * BPF_F_NO_PREALLOC is required for LPM_TRIE.
 */

/* LPM key types — layout must match Go structs IPv4LPMKey / IPv6LPMKey */
struct lpm_key_v4 {
	__u32 prefixlen;  /* significant prefix bits (0-32) */
	__u8  addr[4];    /* IPv4 address in network byte order */
};

struct lpm_key_v6 {
	__u32 prefixlen;  /* significant prefix bits (0-128) */
	__u8  addr[16];   /* IPv6 address in network byte order */
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct lpm_key_v4);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} net_block_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct lpm_key_v6);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} net_block_ipv6 SEC(".maps");

/* Destination ports to block (host byte order). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, __u8);
} net_block_ports SEC(".maps");

/*
 * net_block_counters — per-CPU drop counter for in-kernel network blocks.
 * Index 0: total connections dropped by the IP/subnet/port blocklist.
 * Userspace sums across CPUs and exports as ebpf_guard_net_block_total.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} net_block_counters SEC(".maps");

/* Copy IPv4 address from a __u32 (network byte order) into a 4-byte buffer. */
static __always_inline void copy_ipv4_addr(__u8 *dst, __u32 src)
{
	dst[0] = (__u8)(src & 0xFF);
	dst[1] = (__u8)((src >> 8) & 0xFF);
	dst[2] = (__u8)((src >> 16) & 0xFF);
	dst[3] = (__u8)((src >> 24) & 0xFF);
}

/* Copy IPv6 address from a struct in6_addr pointer. */
static __always_inline void copy_ipv6_addr(__u8 *dst, struct in6_addr *src)
{
	bpf_probe_read_kernel(dst, 16, src);
}

/* Increment the in-kernel network block drop counter (per-CPU). */
static __always_inline void record_net_drop(void)
{
	__u32 idx = 0;
	__u64 *cnt = bpf_map_lookup_elem(&net_block_counters, &idx);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

/*
 * Path-prefix denylist (P1-18b) — in-kernel filtering of file events by path,
 * same LPM-trie mechanism as the IP blocklist above but matching bytes of a
 * path string instead of an address. The trie performs longest-prefix-match
 * on the raw bytes of path_filter_key.path up to prefixlen bits (prefixlen is
 * always a multiple of 8 — whole bytes — set from userspace as
 * 8 * len(prefix_string)).
 *
 * This is a DENYLIST, not an allowlist: an event matching a stored prefix is
 * dropped before it reaches the ring buffer; a path with no matching prefix
 * passes through unfiltered. Per P1-18b's risk note, denylist errors are
 * cheaper than allowlist errors — a missing entry just leaves noise in place,
 * it does not blind the agent to files nobody thought to list.
 *
 * PATH_FILTER_PREFIX_LEN bounds the key size the trie has to walk; prefixes
 * longer than this are truncated by the loader (see path_filter.go).
 */
#define PATH_FILTER_PREFIX_LEN 128

/* LPM key type — layout must match Go struct PathLPMKey in internal/bpf. */
struct path_filter_key {
	__u32 prefixlen;                    /* significant prefix bits (0-1024, multiple of 8) */
	__u8  path[PATH_FILTER_PREFIX_LEN]; /* path prefix bytes */
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct path_filter_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} path_filter_map SEC(".maps");

/*
 * path_key_scratch — per-CPU storage for the LPM lookup key that
 * path_is_denied() builds. See that function for why the key cannot be a
 * stack local.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct path_filter_key);
} path_key_scratch SEC(".maps");

/*
 * path_filter_drop_counters — per-CPU drop counter for in-kernel path-prefix
 * filtering. Index 0: total file events dropped because their path matched a
 * denylisted prefix. Userspace sums across CPUs and exports as
 * ebpf_guard_events_dropped_total{reason="path_denylist"} — without this
 * counter, path filtering would be exactly the silent-blindness failure mode
 * P1-18b warns against: a DNS-collector-shaped bug where the filter works but
 * nothing says so.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} path_filter_drop_counters SEC(".maps");

/* Increment the in-kernel path-filter drop counter (per-CPU). */
static __always_inline void record_path_filter_drop(void)
{
	__u32 idx = 0;
	__u64 *cnt = bpf_map_lookup_elem(&path_filter_drop_counters, &idx);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

/*
 * path_is_denied - returns true if `path` matches a denylisted prefix in
 * path_filter_map. `path` must be a fixed-size buffer of at least
 * PATH_FILTER_PREFIX_LEN bytes (NUL-padded) so the full key is safe to read
 * for the verifier — pass a kernel-side buffer already resolved into an
 * event/scratch struct (struct fd_path::path), never a raw userspace pointer.
 *
 * Increments record_path_filter_drop() on every match so the drop is visible
 * even when the caller only checks the boolean.
 */
static __always_inline bool path_is_denied(const char *path)
{
	__u32 zero = 0;
	struct path_filter_key *key;
	__u8 *val;

	/*
	 * The 132-byte LPM key lives in a per-CPU array, not on the stack.
	 * path_is_denied() is __always_inline, so the buffer would land in the
	 * *caller's* frame; in the file hooks it stacks with the fd path snapshot
	 * and the comm_is_denied() buffer and pushes the frame past the BPF
	 * 512-byte stack limit, which clang rejects at compile time.
	 *
	 * Per-CPU is safe here: the key is filled and consumed by the single
	 * lookup below with no intervening helper that could yield the CPU, and
	 * BPF programs run with preemption disabled.
	 */
	key = bpf_map_lookup_elem(&path_key_scratch, &zero);
	if (!key)
		return false;

	key->prefixlen = PATH_FILTER_PREFIX_LEN * 8;
	__builtin_memcpy(key->path, path, PATH_FILTER_PREFIX_LEN);

	val = bpf_map_lookup_elem(&path_filter_map, key);
	if (!val)
		return false;

	record_path_filter_drop();
	return true;
}

/* Helper to get current process info */
static __always_inline void fill_process_info(struct event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->pid = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;

	/* Parent identity is read here, in the kernel, from
	 * task_struct->real_parent — it is NOT enriched in userspace.
	 *
	 * It used to be zeroed here with a comment blaming verifier trouble
	 * with pointer-chasing through task_struct on kernel 5.15, leaving
	 * /proc/<pid>/status as the only source (LineageTracker.lookupOwnPPID).
	 * That fallback loses the race against any short-lived process: the
	 * task is gone before the event is dequeued, lookupOwnPPID returns 0,
	 * Track() bails out and the alert carries no ProcessTree. Замер №2.9.2
	 * measured the consequence — 34 of 34 incidents without a process
	 * chain were instant processes, and criterion 10 failed at 52.6%.
	 *
	 * The stated verifier concern was disproved by that same run: 5.9.2g's
	 * pid_is_observer() walks real_parent for OBSERVER_MAX_DEPTH hops and
	 * loads on this exact kernel. One hop is strictly cheaper. The read
	 * style mirrors cgroup.bpf.c, which has always done this.
	 *
	 * real_parent, not parent: a task reparented by ptrace keeps its true
	 * ancestry, matching pid_is_observer()'s choice.
	 */
	e->ppid = 0;
	__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	{
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct task_struct *parent;

		if (task) {
			parent = BPF_CORE_READ(task, real_parent);
			if (parent) {
				e->ppid = BPF_CORE_READ(parent, tgid);
				bpf_probe_read_kernel(&e->parent_comm,
						      sizeof(e->parent_comm),
						      BPF_CORE_READ(parent, comm));
			}
		}
	}

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = bpf_ktime_get_ns();
}

#endif /* __EBPF_GUARD_COMMON_H */
