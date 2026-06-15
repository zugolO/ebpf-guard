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

/* Helper macro to reserve space in ring buffer with sampling check */
#define reserve_event_with_sampling(event_type, sample_rate) \
	({ \
		struct event *__e = NULL; \
		if (should_sample(event_type, sample_rate)) { \
			__e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0); \
		} \
		__e; \
	})

/* Helper macro to reserve space in ring buffer (no sampling - legacy) */
#define reserve_event() \
	bpf_ringbuf_reserve(&events, sizeof(struct event), 0)

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

/* Helper to get current process info */
static __always_inline void fill_process_info(struct event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->pid = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;
	/* ppid/parent_comm are enriched in userspace via /proc to avoid
	 * BPF verifier issues with pointer-chasing through task_struct
	 * across complex code paths on kernel 5.15. */
	e->ppid = 0;
	__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = bpf_ktime_get_ns();
}

#endif /* __EBPF_GUARD_COMMON_H */
