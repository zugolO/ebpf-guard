/*
 * syscall.bpf.c - eBPF program for syscall tracing via raw tracepoints.
 * Attaches to sys_enter, sys_exit, and sched_process_exec tracepoints.
 */

/* linux/bpf.h and linux/ptrace.h are superseded by vmlinux.h (included via
 * common.h) when doing CO-RE compilation. Do not re-add them here. */
/* 8.2 B1: карты из common.h, нужные этому объекту (см. шапку common.h). */
#define EG_MAPS_PROC_ARGS
#define EG_MAPS_SAMPLING
#define EG_MAPS_MAP_FULL
#define EG_MAPS_RINGBUF
#define EG_MAPS_COMM_FILTER
#define EG_MAPS_SYSCALL_FILTER
#define EG_MAPS_KERNEL_FILTER
#define EG_MAPS_OBSERVER
#define EG_MAPS_AGENT_PID
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Raw tracepoint argument structure for sys_enter */
struct sys_enter_args {
	unsigned long long unused;
	long syscall_nr;
	unsigned long args[6];
};

/* Raw tracepoint argument structure for sys_exit */
struct sys_exit_args {
	unsigned long long unused;
	long syscall_nr;
	long ret;
};

/* Map to store syscall entry args for matching with exit.
 * LRU eviction ensures the map does not overflow under burst workloads,
 * dropping the oldest unfinished entry (least-used PID) rather than rejecting
 * new inserts with -E2BIG. 4096 entries (8.2 B2, №538; было 32768 при 10
 * живых записях): запись живёт от sys_enter до sys_exit одного вызова, то есть
 * столько, сколько потоков одновременно сидят внутри отслеживаемого вызова.
 * Map-full drops (when all entries are in use) are tracked via
 * map_full_counters[MAP_FULL_IDX_SYSCALL_ARGS] and exported as
 * ebpf_guard_bpf_map_full_total{map_name="syscall_args"}.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct sys_enter_args);
} syscall_args SEC(".maps");

/*
 * Волна 8.5, F1: предикат аргументов номера, ГЕНЕРИРУЕМЫЙ userspace'ом из
 * загруженных правил (internal/correlator/kernelpred.go). Номер без записи
 * (nterms == 0) идёт целиком, как до F1. Событие номера с предикатом уходит в
 * кольцо, только если выполнены ВСЕ конъюнкты: args[arg] ∈ vals[0..nvals).
 * Предикат — необходимое условие совпадения правила, поэтому ядро не теряет
 * ни одного совпадения; остальное дочищает userspace. Невалидная запись
 * (arg > 5, nvals == 0) отключает отбор для номера — отказ в сторону «пропустить».
 *
 * Раскладка обязана совпадать с internal/bpf/syscall_pred.go (SyscallPred).
 */
#define EG_PRED_TERMS  2
#define EG_PRED_VALUES 8

struct syscall_pred_term {
	__u8  arg;
	__u8  nvals;
	__u8  pad[6];
	__u64 vals[EG_PRED_VALUES];
};

struct syscall_pred {
	__u8  nterms;
	__u8  pad[7];
	struct syscall_pred_term terms[EG_PRED_TERMS];
};

_Static_assert(sizeof(struct syscall_pred_term) == 8 + 8 * EG_PRED_VALUES,
	       "syscall_pred_term layout drifted from internal/bpf/syscall_pred.go");
_Static_assert(sizeof(struct syscall_pred) == 8 + EG_PRED_TERMS * (8 + 8 * EG_PRED_VALUES),
	       "syscall_pred layout drifted from internal/bpf/syscall_pred.go");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, struct syscall_pred);
} syscall_pred_map SEC(".maps");

/*
 * Волна 8.5, F2: счётчик того, что предикат отбросил. Профайлер слоя anomaly
 * знает о номере вызова «бывал ли он у этой нагрузки» и сколько наблюдений
 * набрано; без поштучных событий он берёт это отсюда (profiler.IngestSyscallCounts).
 * Считаем КАЖДЫЙ отброшенный вызов программы (enter и exit по отдельности —
 * так же, как поштучно приходили события): профиль из счётчиков тождественен
 * профилю из событий. LRU: переполнение вытесняет самую старую пару, а не
 * отказывает во вставке.
 *
 * Не per-CPU (решение владельца 12.10, вопрос 7): память карты не зависит от
 * числа CPU (на 64 CPU per-CPU вариант стоил бы ≈17 МиБ). Счёт растёт атомарным
 * сложением; конкуренцию на горячих ключах (один tgid+nr с разных CPU) судит
 * CPU агента в паре A/B.
 */
struct syscall_count_key {
	__u32 tgid;
	__u32 nr;
};

struct syscall_count_val {
	__u64 n;
	__u64 cgroup_id;
	__u8  comm[COMM_LEN];
};

_Static_assert(sizeof(struct syscall_count_key) == 8,
	       "syscall_count_key layout is mirrored by bpf.SyscallCountKey");
_Static_assert(sizeof(struct syscall_count_val) == 8 + 8 + COMM_LEN,
	       "syscall_count_val layout is mirrored by bpf.SyscallCountValue");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct syscall_count_key);
	__type(value, struct syscall_count_val);
} syscall_counts SEC(".maps");

/*
 * Волна 8.5, F3: самоисключение служебных bpf() агента. Агент читает и пишет
 * собственные карты (lookup/update/get_next_key/batch) — ядро показывает ему же
 * каждый такой вызов событием nr=321 (enter и exit), которое он сам разбирает.
 * От СВОЕГО tgid (agent_pid_map, программируется из Go) служебные cmd не
 * отправляются в кольцо; считаются в syscall_counts (профиль нагрузки агента
 * получает их счётчиком, как отброшенное предикатом) и в syscall_self_excluded.
 *
 * Служебные cmd — список ПОЗИТИВНО: 1 MAP_LOOKUP_ELEM, 2 MAP_UPDATE_ELEM,
 * 4 MAP_GET_NEXT_KEY, 21 MAP_LOOKUP_AND_DELETE_ELEM, 24 MAP_LOOKUP_BATCH,
 * 25 MAP_LOOKUP_AND_DELETE_BATCH, 26 MAP_UPDATE_BATCH, 27 MAP_DELETE_BATCH.
 * Всё остальное — в том числе разрушительные {0,3,5,6,9,33}, которые читают
 * правила ebpf-subversion / rootkit_bpf_* / drift_dangerous_syscall, — идёт
 * как раньше. 3 (MAP_DELETE_ELEM) в служебные НЕ входит: он в списке
 * разрушительных у владельца.
 *
 * Метка в syscall_args: enter исключённого вызова кладёт запись с magic в
 * args[5] (у bpf() шестого аргумента нет), exit по ней же узнаёт «это мой» и
 * тоже молчит — а не по отсутствию записи, которое бывает и у обычного вызова,
 * выпавшего из выборки.
 */
#define EG_SELF_EXCL_NR_BPF 321
#define EG_SELF_EXCL_MAGIC 0x4547f3f3f3f3f3f3UL

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} syscall_self_excluded SEC(".maps");

static __always_inline bool bpf_cmd_is_service(unsigned long cmd)
{
	switch (cmd) {
	case 1: case 2: case 4: case 21: case 24: case 25: case 26: case 27:
		return true;
	default:
		return false;
	}
}

static __always_inline void syscall_self_excluded_inc(void)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(&syscall_self_excluded, &key);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline struct syscall_pred *syscall_pred_lookup(__s64 nr)
{
	__u32 key;
	struct syscall_pred *p;

	if (nr < 0 || nr >= 512)
		return NULL;
	key = (__u32)nr;
	p = bpf_map_lookup_elem(&syscall_pred_map, &key);
	if (!p || p->nterms == 0)
		return NULL;
	return p;
}

/* args[idx] константными смещениями: переменный индекс в ctx верификатор не пустит. */
static __always_inline unsigned long pred_arg(const unsigned long *a, __u8 idx)
{
	if (idx == 0) return a[0];
	if (idx == 1) return a[1];
	if (idx == 2) return a[2];
	if (idx == 3) return a[3];
	if (idx == 4) return a[4];
	return a[5];
}

static __always_inline bool syscall_pred_match(const struct syscall_pred *p, const unsigned long *a)
{
	int t, i;

#pragma unroll
	for (t = 0; t < EG_PRED_TERMS; t++) {
		const struct syscall_pred_term *term;
		unsigned long v;
		bool hit = false;

		if (t >= p->nterms)
			break;
		term = &p->terms[t];
		if (term->arg > 5 || term->nvals == 0 || term->nvals > EG_PRED_VALUES)
			continue; /* невалидный конъюнкт не отбрасывает ничего */
		v = pred_arg(a, term->arg);
#pragma unroll
		for (i = 0; i < EG_PRED_VALUES; i++) {
			if (i >= term->nvals)
				break;
			if (term->vals[i] == v) {
				hit = true;
				break;
			}
		}
		if (!hit)
			return false;
	}
	return true;
}

/* true: у номера есть предикат и аргументы этого вызова его НЕ выполняют. */
static __always_inline bool syscall_pred_rejects_enter(struct sys_enter_args *ctx)
{
	struct syscall_pred *p = syscall_pred_lookup(ctx->syscall_nr);
	unsigned long a[6];

	if (!p)
		return false;
	if (bpf_probe_read_kernel(&a, sizeof(a), &ctx->args) < 0)
		return false;
	return !syscall_pred_match(p, a);
}

static __always_inline void syscall_count_filtered(__s64 nr)
{
	struct syscall_count_key k = {};
	struct syscall_count_val *v;

	k.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	k.nr = (__u32)nr;
	v = bpf_map_lookup_elem(&syscall_counts, &k);
	if (!v) {
		struct syscall_count_val nv = {};

		nv.n = 1;
		nv.cgroup_id = bpf_get_current_cgroup_id();
		bpf_get_current_comm(nv.comm, sizeof(nv.comm));
		if (bpf_map_update_elem(&syscall_counts, &k, &nv, BPF_NOEXIST) == 0)
			return;
		/* другой CPU вставил ту же пару первым: считаем в его запись */
		v = bpf_map_lookup_elem(&syscall_counts, &k);
		if (!v)
			return;
	}
	__sync_fetch_and_add(&v->n, 1);
	/* comm меняется на exec: хранится последний, иначе счёт ушёл бы в чужую нагрузку */
	bpf_get_current_comm(v->comm, sizeof(v->comm));
}

SEC("tp/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx)
{
	struct event *e;
	__u64 pid_tgid;
	bool pred_rejects = false;

	/* BPF-side content filtering: drop before touching the ring buffer */
	if (kernel_filter_enabled()) {
		if (comm_is_denied())
			return 0;
		if (!syscall_is_monitored(ctx->syscall_nr))
			return 0;
		/* 8.5 F1: предикат аргументов номера (карта программируется из правил). */
		pred_rejects = syscall_pred_rejects_enter(ctx);
		/* 8.5 F3: служебный bpf() самого агента — не событие. */
		if (ctx->syscall_nr == EG_SELF_EXCL_NR_BPF && bpf_cmd_is_service(ctx->args[0]) &&
		    pid_is_agent()) {
			struct sys_enter_args mark = {};
			__u64 key = bpf_get_current_pid_tgid();

			mark.syscall_nr = ctx->syscall_nr;
			mark.args[0] = ctx->args[0];
			mark.args[5] = EG_SELF_EXCL_MAGIC;
			bpf_map_update_elem(&syscall_args, &key, &mark, BPF_ANY);
			syscall_self_excluded_inc();
			syscall_count_filtered(ctx->syscall_nr);
			return 0;
		}
	}

	/* 5.9.2g: measurement-harness tree, dropped in the kernel before the ring
	 * buffer. Placed here — after the content filters, immediately before the
	 * reserve — so the counter means "events that would otherwise have been
	 * emitted", which is what 5.9a's userspace counter meant. */
	if (observer_should_drop())
		return 0;

	/* 8.5 F1/F2: отброшено предикатом — считаем и не трогаем кольцо. Счёт
	 * после observer_should_drop: поддерево измерителя в ядре и так не
	 * доезжало бы до профайлера. */
	if (pred_rejects) {
		syscall_count_filtered(ctx->syscall_nr);
		return 0;
	}

	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_SYSCALL, 0);
	if (!e)
		return 0;

	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_SYSCALL;

	/* Fill syscall-specific data */
	e->syscall.nr = ctx->syscall_nr;
	e->syscall.ret = 0; /* Will be filled on exit */

	/* Copy syscall arguments */
	bpf_probe_read_kernel(&e->syscall.args, sizeof(e->syscall.args), &ctx->args);

	/* Store args for exit matching.  bpf_map_update_elem requires fp/stack
	 * pointer for value; the raw context pointer (type=ctx) is rejected by
	 * the verifier, so copy the needed fields to a stack variable first. */
	pid_tgid = bpf_get_current_pid_tgid();
	{
		struct sys_enter_args entry_copy = {};
		entry_copy.syscall_nr = ctx->syscall_nr;
		entry_copy.args[0] = ctx->args[0];
		entry_copy.args[1] = ctx->args[1];
		entry_copy.args[2] = ctx->args[2];
		entry_copy.args[3] = ctx->args[3];
		entry_copy.args[4] = ctx->args[4];
		entry_copy.args[5] = ctx->args[5];
		if (bpf_map_update_elem(&syscall_args, &pid_tgid, &entry_copy, BPF_NOEXIST) == -E2BIG)
			record_map_full(MAP_FULL_IDX_SYSCALL_ARGS);
	}

	submit_event(e);
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_args *ctx)
{
	struct event *e;
	struct sys_enter_args *entry_args;
	__u64 pid_tgid;
	bool has_pred = false;

	/* BPF-side content filtering: drop before touching the ring buffer */
	if (kernel_filter_enabled()) {
		if (comm_is_denied())
			return 0;
		if (!syscall_is_monitored(ctx->syscall_nr))
			return 0;
		has_pred = syscall_pred_lookup(ctx->syscall_nr) != NULL;
	}

	/* 5.9.2g: measurement-harness tree, dropped in the kernel before the ring
	 * buffer. Placed here — after the content filters, immediately before the
	 * reserve — so the counter means "events that would otherwise have been
	 * emitted", which is what 5.9a's userspace counter meant. */
	if (observer_should_drop())
		return 0;

	/* Args stored by the matching sys_enter. For a number with a predicate the
	 * entry exists only when enter PASSED the predicate (it stores after its
	 * filters), so a missing entry means "enter was rejected": the exit is
	 * rejected with it, and counted like the enter was (8.5 F1/F2); an entry left
	 * by another syscall (enter without exit) counts as missing. Numbers
	 * without a predicate keep the old behaviour — exit is emitted with zero
	 * args when the entry is gone. */
	pid_tgid = bpf_get_current_pid_tgid();
	entry_args = bpf_map_lookup_elem(&syscall_args, &pid_tgid);
	if (has_pred && (!entry_args || entry_args->syscall_nr != ctx->syscall_nr)) {
		/* Запись чужого вызова (enter без exit: execve, exit_group) — не наша. */
		syscall_count_filtered(ctx->syscall_nr);
		return 0;
	}

	/* 8.5 F3: exit служебного bpf() агента — по метке, оставленной enter. */
	/* pid_is_agent() обязателен и здесь: args[5] у настоящего вызова — регистр r9
	 * пользователя, и чужой процесс мог бы выставить magic и спрятать свой exit. */
	if (entry_args && entry_args->syscall_nr == ctx->syscall_nr &&
	    ctx->syscall_nr == EG_SELF_EXCL_NR_BPF &&
	    entry_args->args[5] == EG_SELF_EXCL_MAGIC && pid_is_agent()) {
		bpf_map_delete_elem(&syscall_args, &pid_tgid);
		syscall_self_excluded_inc();
		syscall_count_filtered(ctx->syscall_nr);
		return 0;
	}

	/* Reserve space in ring buffer with sampling */
	e = reserve_event_with_sampling(EVENT_TYPE_SYSCALL, 0);
	if (!e)
		return 0;

	/* Fill process information */
	fill_process_info(e);
	e->type = EVENT_TYPE_SYSCALL;

	/* Fill syscall-specific data */
	e->syscall.nr = ctx->syscall_nr;
	e->syscall.ret = ctx->ret;

	if (entry_args) {
		bpf_probe_read_kernel(&e->syscall.args, sizeof(e->syscall.args),
			&entry_args->args);
		bpf_map_delete_elem(&syscall_args, &pid_tgid);
	} else {
		__builtin_memset(&e->syscall.args, 0, sizeof(e->syscall.args));
	}

	submit_event(e);
	return 0;
}

/*
 * proc_args_scratch - per-CPU scratchpad for trace_sched_process_exec.
 * struct proc_args is 516 bytes, exceeding the 512-byte BPF stack limit,
 * so we use a per-CPU array as scratch space instead of a stack variable.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proc_args);
} proc_args_scratch SEC(".maps");

/*
 * trace_sched_process_exec - populate proc_args_map on every exec.
 *
 * Reads argv from task_struct->mm->arg_start..arg_end (BTF CO-RE) and stores
 * a NUL-terminated, space-joined copy in proc_args_map keyed by TGID.
 * Requires kernel 5.15+ with BTF support; falls back to /proc/PID/cmdline
 * in userspace when this program fails to load (see collector/syscall.go).
 */
SEC("tp/sched/sched_process_exec")
int trace_sched_process_exec(void *ctx)
{
	__u32 scratch_key = 0;
	struct proc_args *pa;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long arg_start, arg_end;
	long args_len, read_len;

	pa = bpf_map_lookup_elem(&proc_args_scratch, &scratch_key);
	if (!pa)
		return 0;

	__builtin_memset(pa, 0, sizeof(*pa));

	/* 6.0j/№210: stamp the entry with the moment of the exec itself. The
	 * sys_enter and sys_exit records of this same execve are reserved before
	 * and after this point, so userspace can attach argv to the exit record
	 * only (pa->exec_ts < e->timestamp) without guessing from argv[0]. */
	pa->exec_ts = bpf_ktime_get_ns();

	task = (struct task_struct *)bpf_get_current_task();
	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	arg_start = BPF_CORE_READ(mm, arg_start);
	arg_end   = BPF_CORE_READ(mm, arg_end);
	args_len  = (long)(arg_end - arg_start);
	if (args_len <= 0)
		return 0;

	if (args_len >= PROC_ARGS_MAX) {
		read_len = PROC_ARGS_MAX - 1;
		pa->truncated = 1;
	} else {
		read_len = args_len;
	}
	/* Bounds check lets the verifier prove read_len is in [1, PROC_ARGS_MAX-1]. */
	if (read_len <= 0 || read_len >= PROC_ARGS_MAX)
		return 0;

	if (bpf_probe_read_user(pa->args, (size_t)read_len, (void *)arg_start) < 0)
		return 0;

	/* NUL bytes between argv entries are replaced by userspace when reading
	 * proc_args_map; the 511-iteration unrolled loop caused the verifier to
	 * reject the program as too large (>1M instructions processed). */

	bpf_map_update_elem(&proc_args_map, &tgid, pa, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
