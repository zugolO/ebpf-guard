/*
 * fileaccess.bpf.c - eBPF program for file access monitoring with fd→path enrichment.
 *
 * fd→path enrichment design:
 *   1. sys_enter_openat                    → store filename in fd_scratch_map keyed by pid_tgid
 *   2. sys_exit_openat / sys_exit_openat2  → move scratch entry to fd_path_map[(tgid<<32|fd)]
 *   3. sys_enter_close                     → delete fd_path_map entry
 *   4. sys_enter_read / sys_enter_write    → look up fd_path_map BEFORE reserving a ring
 *      buffer slot, check the path-prefix denylist (P1-18b), then embed the resolved path
 *      in the event only if it passes.
 *
 * Note there is deliberately no sys_enter_openat2 here: openat2() takes its
 * flags in a struct open_how rather than a register, so it needs its own enter
 * handler rather than sharing trace_open. Only its exit is hooked today, which
 * means an openat2() commits whatever the calling thread's last openat() left
 * in scratch. Pre-existing limitation, tracked separately from P1-18b — the
 * path filter inherits it rather than introducing it.
 *
 * Memory: LRU fd_path_map at 65536 entries × (8B key + 257B value) ≈ 17 MB.
 *         Scratch map sized to max in-flight opens (4096 entries).
 *
 * P1-18b path-prefix filtering: path_filter_map (bpf/common.h) is an LPM-trie
 * denylist. trace_open checks it against the filename argument (read from
 * userspace exactly once, see filename_read) before reserving;
 * trace_read/trace_write check it against a snapshot of the fd_path_map entry
 * resolved by the open() path, also before reserving. The
 * fd_scratch_map → fd_path_map handoff always runs regardless of the filter
 * decision, so a denylisted open() still leaves a path in fd_path_map for
 * later read/write filtering.
 *
 * All programs use raw tracepoint context (struct trace_event_raw_sys_enter /
 * struct trace_event_raw_sys_exit) instead of the BPF_PROG macro.  BPF_PROG
 * relies on CO-RE rewriting of per-syscall BTF struct access; when those structs
 * are absent from kernel BTF (e.g. trace_event_raw_sys_enter_read on 5.15) the
 * verifier rejects the program with "invalid bpf_context access off=0 size=8".
 */

/* linux/ headers are superseded by vmlinux.h (included via common.h)
 * when doing CO-RE compilation. Do not re-add them here. */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Value stored in both scratch and fd→path maps. */
struct fd_path {
	char path[FILENAME_LEN];
	__u8 truncated; /* 1 if path was longer than FILENAME_LEN-1 bytes */
};

/*
 * fd_scratch_map — temporary per-thread storage for the filename between
 * sys_enter_openat and sys_exit_openat.
 * key: pid_tgid (__u64 from bpf_get_current_pid_tgid())
 * value: struct fd_path
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct fd_path);
} fd_scratch_map SEC(".maps");

/*
 * fd_path_map — durable fd→path table for the lifetime of an open fd.
 * key: (tgid << 32) | fd
 * value: struct fd_path
 * LRU eviction prevents map-full errors under high fd churn.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct fd_path);
} fd_path_map SEC(".maps");

/*
 * Read the openat() filename argument from userspace exactly once into `out`.
 *
 * trace_open needs the same bytes three times: to populate fd_scratch_map, to
 * test the P1-18b path denylist, and (if it survives) to fill the event. Doing
 * a separate bpf_probe_read_user_str() per use would triple the userspace-read
 * cost of the highest-volume hook in the agent — the very cost wave 4 exists
 * to cut — and open a TOCTOU hole: userspace owns that buffer and may rewrite
 * it between reads, so the denylist could be checked against one path while a
 * different one is stored and reported.
 */
static __always_inline void filename_read(struct fd_path *out, const char *user_filename)
{
	long ret = bpf_probe_read_user_str(out->path, sizeof(out->path), user_filename);

	out->truncated = (ret == (long)sizeof(out->path)) ? 1 : 0;
}

/* Store an already-read filename into the scratch map for the current thread. */
static __always_inline void scratch_store(const struct fd_path *scratch)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&fd_scratch_map, &pid_tgid, scratch, BPF_ANY);
}

/* Move scratch entry to fd_path_map for the given fd, then delete scratch. */
static __always_inline void fd_commit(__u32 tgid, __s64 fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct fd_path *scratch;

	if (fd < 0)
		goto cleanup;

	scratch = bpf_map_lookup_elem(&fd_scratch_map, &pid_tgid);
	if (!scratch)
		goto cleanup;

	__u64 map_key = ((__u64)tgid << 32) | (__u64)(unsigned int)fd;
	bpf_map_update_elem(&fd_path_map, &map_key, scratch, BPF_ANY);

cleanup:
	bpf_map_delete_elem(&fd_scratch_map, &pid_tgid);
}

/*
 * fd_lookup_scratch — per-CPU snapshot buffer for fd_path_lookup().
 *
 * trace_read/trace_write cannot hold the `struct fd_path` snapshot on the
 * stack: at FILENAME_LEN=256 it is ~264 bytes, and stacked with the buffers
 * path_is_denied() (struct path_filter_key) and comm_is_denied() (char
 * comm[COMM_LEN]) allocate in the same frame it exceeds the BPF 512-byte
 * stack limit, which clang rejects outright ("Looks like the BPF stack limit
 * of 512 bytes is exceeded"). A per-CPU array gives each snapshot a
 * map-backed home instead.
 *
 * Per-CPU is sufficient despite the snapshot living across the
 * reserve_event_with_sampling() call: BPF tracepoint programs run with
 * preemption disabled, so the same CPU cannot re-enter these hooks and
 * overwrite the entry mid-use.
 *
 * trace_open keeps its on-stack `struct fd_path` — it is the only large buffer
 * in that frame and stays under the limit.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fd_path);
} fd_lookup_scratch SEC(".maps");

/*
 * fd_path_lookup - look up fd→path without touching the ring buffer, copying
 * the result into a caller-owned snapshot. Used by trace_read/trace_write to
 * check the path-prefix denylist BEFORE reserving an event, so a filtered
 * path never costs a ring buffer slot (P1-18b: those two hooks reserve before
 * path resolution today, which means path filtering there would only save
 * correlation work, not ring-buffer bandwidth, unless the lookup is moved
 * ahead of reserve_event_with_sampling — this is that move).
 *
 * The snapshot is not an optimisation detail, it is required for correctness:
 * fd_path_map is a BPF_MAP_TYPE_LRU_HASH, so the element a bare
 * bpf_map_lookup_elem() pointer refers to may be evicted and reused by
 * another CPU at any point after the lookup returns. Holding that pointer
 * across reserve_event_with_sampling() — which can block on ring-buffer
 * space — and only dereferencing it afterwards would let the event carry a
 * different file's path than the one the denylist was checked against. That
 * is both a wrong-attribution bug and a filter bypass (check /var/log/x,
 * report /etc/shadow, or vice versa).
 *
 * Returns true if the fd had a resolved path (and *out is filled), false
 * otherwise (e.g. opened before the agent started, or opened by a process
 * whose comm is denied — per trace_open those still populate fd_path_map).
 */
static __always_inline bool fd_path_lookup(__u32 tgid, __u32 fd, struct fd_path *out)
{
	__u64 map_key = ((__u64)tgid << 32) | (__u64)fd;
	struct fd_path *fdp = bpf_map_lookup_elem(&fd_path_map, &map_key);

	if (!fdp)
		return false;

	__builtin_memcpy(out->path, fdp->path, FILENAME_LEN);
	out->truncated = fdp->truncated;
	return true;
}

/*
 * Tracepoint for sys_enter_openat — capture filename into scratch map.
 * args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode.
 */
SEC("tp/syscalls/sys_enter_openat")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];
	int flags = (int)ctx->args[2];
	umode_t mode = (umode_t)ctx->args[3];
	struct fd_path path = {};
	struct event *e;

	/* Self-exclusion: drop events from the agent's own PID */
	if (pid_is_agent())
		return 0;

	/* BPF-side content filtering: drop before touching the ring buffer */
	if (kernel_filter_enabled()) {
		if (comm_is_denied())
			return 0;
	}

	/* One userspace read, three uses — see filename_read(). */
	filename_read(&path, filename);

	/*
	 * scratch_store() runs unconditionally, even when the path filter below
	 * drops the open event itself: fd_path_map still needs the resolved path
	 * so a later read/write on this fd can be filtered by the same denylist
	 * (see trace_read/trace_write). Without this, filtering out open() would
	 * leave read/write with no path to check and they would default to
	 * "unknown" — passing everything through, which defeats the filter.
	 */
	scratch_store(&path);

	if (kernel_filter_enabled() && path_is_denied(path.path))
		return 0;

	/* 5.9.2g: measurement-harness tree, dropped in the kernel before the ring
	 * buffer. Placed here — after the content filters, immediately before the
	 * reserve — so the counter means "events that would otherwise have been
	 * emitted", which is what 5.9a's userspace counter meant. */
	if (observer_should_drop())
		return 0;

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_OPEN;
	e->file.flags = flags;
	e->file.mode = mode;
	__builtin_memcpy(e->file.filename, path.path, FILENAME_LEN);
	/*
	 * Now that the path is read once up front, the open event can report the
	 * same truncation flag read/write already report from fd_path_map instead
	 * of a hardcoded 0 — previously this hook read the name straight into the
	 * event and had no return value to derive the flag from.
	 */
	e->file.fd_path_truncated = path.truncated;

	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_exit_openat — commit scratch→fd_path_map using the returned fd.
 */
SEC("tp/syscalls/sys_exit_openat")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	fd_commit(tgid, ctx->ret);
	return 0;
}

/*
 * Tracepoint for sys_exit_openat2 — commit scratch→fd_path_map.
 */
SEC("tp/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	fd_commit(tgid, ctx->ret);
	return 0;
}

/*
 * Tracepoint for sys_enter_close — evict fd_path_map entry on close(2).
 * args[0] = fd.
 */
SEC("tp/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
	unsigned int fd = (unsigned int)ctx->args[0];
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	__u64 map_key = ((__u64)tgid << 32) | (__u64)fd;

	bpf_map_delete_elem(&fd_path_map, &map_key);
	return 0;
}

/*
 * chmod_emit — общее тело трёх chmod-хуков (волна 6.2.1, слой 3).
 *
 * path == NULL означает «путь не разрешён» (fchmod по дескриптору, которого
 * нет в fd_path_map: файл открыли до старта агента, либо запись вытеснена
 * LRU). Событие в этом случае ВСЁ РАВНО отправляется, с пустым filename.
 * Это намеренно: молча проглотить chmod, пути которого мы не знаем, значит
 * заменить прежний шум тишиной, а правило обязано иметь возможность отличить
 * «chmod по пути, который меня не касается» от «chmod, чей путь неизвестен».
 * Первое отсекается префиксом в правиле, второе видно как алерт с пустым
 * file.path и считается отдельно на стороне userspace.
 */
static __always_inline void chmod_emit(const char *path, __u8 truncated, umode_t mode)
{
	struct event *e;

	if (kernel_filter_enabled() && path && path_is_denied(path))
		return;

	if (observer_should_drop())
		return;

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_CHMOD;
	e->file.flags = 0;
	/* mode здесь — НОВЫЙ режим, который просит chmod, а не флаги открытия:
	 * единственное место, где правило может увидеть «выставлен бит
	 * исполнения», не читая файл. */
	e->file.mode = mode;
	__builtin_memset(&e->file.filename, 0, sizeof(e->file.filename));
	e->file.fd_path_truncated = truncated;

	if (path)
		__builtin_memcpy(e->file.filename, path, FILENAME_LEN);

	submit_event(e);
}

/*
 * Tracepoint for sys_enter_chmod — args[0]=filename (user pointer), args[1]=mode.
 *
 * На arm64 и на новых x86-конфигурациях sys_chmod может отсутствовать вовсе
 * (glibc реализует chmod через fchmodat). Привязка тогда не удастся, и это
 * НЕ тихий случай: userspace считает неудачу привязки в
 * ebpf_guard_file_hook_attach_total{hook=...,result="error"} и пишет
 * предупреждение — иначе «ноль chmod-алертов» невозможно отличить от
 * «chmod никто не звал».
 */
SEC("tp/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
	struct fd_path path = {};

	if (pid_is_agent())
		return 0;
	if (kernel_filter_enabled() && comm_is_denied())
		return 0;

	filename_read(&path, (const char *)ctx->args[0]);
	chmod_emit(path.path, path.truncated, (umode_t)ctx->args[1]);
	return 0;
}

/*
 * Tracepoint for sys_enter_fchmodat — args[0]=dfd, args[1]=filename, args[2]=mode.
 *
 * Относительный путь при dfd != AT_FDCWD остаётся относительным: разрешать
 * его до абсолютного здесь нечем (нужен обход dentry родителя), и правила
 * с префиксом на него не совпадут. Это недоразрешение видно как алерт с
 * относительным file.path, а не как пропажа события; довести до абсолютного
 * пути — работа отдельной волны, у которой будет свой контроль.
 */
SEC("tp/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	struct fd_path path = {};

	if (pid_is_agent())
		return 0;
	if (kernel_filter_enabled() && comm_is_denied())
		return 0;

	filename_read(&path, (const char *)ctx->args[1]);
	chmod_emit(path.path, path.truncated, (umode_t)ctx->args[2]);
	return 0;
}

/*
 * Tracepoint for sys_enter_fchmod — args[0]=fd, args[1]=mode.
 *
 * Путь берётся из fd_path_map — той самой таблицы, которую заполняет
 * trace_open этого же объекта. Именно поэтому весь слой 3 живёт здесь, а не
 * в syscall.bpf.c: там fd_path_map — чужая карта другого BPF-объекта, и
 * делить её пришлось бы через пиннинг в bpffs, которого в этом агенте нет.
 */
SEC("tp/syscalls/sys_enter_fchmod")
int trace_fchmod(struct trace_event_raw_sys_enter *ctx)
{
	unsigned int fd = (unsigned int)ctx->args[0];
	__u32 zero = 0;
	struct fd_path *fdp;
	__u64 pid_tgid;
	__u32 tgid;

	if (pid_is_agent())
		return 0;
	if (kernel_filter_enabled() && comm_is_denied())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (__u32)(pid_tgid >> 32);

	fdp = bpf_map_lookup_elem(&fd_lookup_scratch, &zero);
	if (!fdp)
		return 0;

	if (!fd_path_lookup(tgid, fd, fdp)) {
		chmod_emit(NULL, 0, (umode_t)ctx->args[1]);
		return 0;
	}
	chmod_emit(fdp->path, fdp->truncated, (umode_t)ctx->args[1]);
	return 0;
}

/*
 * Tracepoint for sys_enter_read — emit event with fd-resolved filename.
 * args[0]=fd.  Raw context avoids "invalid bpf_context access off=0 size=8"
 * that BPF_PROG causes on kernels lacking trace_event_raw_sys_enter_read BTF.
 */
SEC("tp/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx)
{
	unsigned int fd = (unsigned int)ctx->args[0];
	__u32 zero = 0;
	struct event *e;
	struct fd_path *fdp;
	bool have_path;
	__u64 pid_tgid;
	__u32 tgid;

	/* Self-exclusion: drop events from the agent's own PID.
	 * read() is the highest-volume of the three file hooks (SQLite page reads,
	 * audit.jsonl, rule reloads), so omitting the check here would leave most
	 * of the agent's self-generated file stream in place.
	 */
	if (pid_is_agent())
		return 0;

	/* BPF-side content filtering: drop before touching the ring buffer */
	if (kernel_filter_enabled()) {
		if (comm_is_denied())
			return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (__u32)(pid_tgid >> 32);

	/*
	 * P1-18b: resolve the path BEFORE reserving a ring buffer slot, not
	 * after. reserve_event_with_sampling() used to run first and
	 * enrich_from_fd() second, which meant a path-prefix filter here would
	 * only have discarded the event post-copy — it would still have paid
	 * for the ring buffer reservation this hook exists to avoid.
	 *
	 * fd_path_lookup snapshots the entry rather than returning a map pointer;
	 * see its comment for why holding an LRU-map pointer across the reserve
	 * below would be a filter bypass, not just a style issue.
	 */
	fdp = bpf_map_lookup_elem(&fd_lookup_scratch, &zero);
	if (!fdp)
		return 0;

	have_path = fd_path_lookup(tgid, fd, fdp);
	if (kernel_filter_enabled() && have_path && path_is_denied(fdp->path))
		return 0;

	/* 5.9.2g: measurement-harness tree, dropped in the kernel before the ring
	 * buffer. Placed here — after the content filters, immediately before the
	 * reserve — so the counter means "events that would otherwise have been
	 * emitted", which is what 5.9a's userspace counter meant. */
	if (observer_should_drop())
		return 0;

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_READ;
	e->file.flags = 0;
	e->file.mode = 0;
	__builtin_memset(&e->file.filename, 0, sizeof(e->file.filename));
	e->file.fd_path_truncated = 0;

	if (have_path) {
		__builtin_memcpy(e->file.filename, fdp->path, FILENAME_LEN);
		e->file.fd_path_truncated = fdp->truncated;
	}

	submit_event(e);
	return 0;
}

/*
 * Tracepoint for sys_enter_write — emit event with fd-resolved filename.
 * args[0]=fd.
 */
SEC("tp/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
	unsigned int fd = (unsigned int)ctx->args[0];
	__u32 zero = 0;
	struct event *e;
	struct fd_path *fdp;
	bool have_path;
	__u64 pid_tgid;
	__u32 tgid;

	/* Self-exclusion: drop events from the agent's own PID */
	if (pid_is_agent())
		return 0;

	/* BPF-side content filtering: drop before touching the ring buffer */
	if (kernel_filter_enabled()) {
		if (comm_is_denied())
			return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (__u32)(pid_tgid >> 32);

	/* P1-18b: resolve path before reserving — see trace_read for rationale.
	 * Snapshot lives in fd_lookup_scratch, not on the stack — see that map's
	 * comment for the 512-byte stack limit this avoids. */
	fdp = bpf_map_lookup_elem(&fd_lookup_scratch, &zero);
	if (!fdp)
		return 0;

	have_path = fd_path_lookup(tgid, fd, fdp);
	if (kernel_filter_enabled() && have_path && path_is_denied(fdp->path))
		return 0;

	/* 5.9.2g: measurement-harness tree, dropped in the kernel before the ring
	 * buffer. Placed here — after the content filters, immediately before the
	 * reserve — so the counter means "events that would otherwise have been
	 * emitted", which is what 5.9a's userspace counter meant. */
	if (observer_should_drop())
		return 0;

	e = reserve_event_with_sampling(EVENT_TYPE_FILE_ACCESS, 0);
	if (!e)
		return 0;

	fill_process_info(e);
	e->type = EVENT_TYPE_FILE_ACCESS;
	e->file.op = FILE_OP_WRITE;
	e->file.flags = 0;
	e->file.mode = 0;
	__builtin_memset(&e->file.filename, 0, sizeof(e->file.filename));
	e->file.fd_path_truncated = 0;

	if (have_path) {
		__builtin_memcpy(e->file.filename, fdp->path, FILENAME_LEN);
		e->file.fd_path_truncated = fdp->truncated;
	}

	submit_event(e);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
