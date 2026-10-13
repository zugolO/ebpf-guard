/*
 * proctable.bpf.c — таблица процессов в ядре (волна 8.5, P1).
 *
 * Хуки sched_process_fork / sched_process_exec / sched_process_exit ведут запись
 * pid → {ppid, start_boottime, comm, exe dev/ino, exec filename, exit_ts}. Userspace
 * читает цепочку предков точечным lookup'ом (internal/bpf/proctable.go), когда алерту
 * нужен process_tree: без Go-карт по шардам, без /proc, без TTL-уборки.
 *
 * ДВЕ карты, а не один LRU (находка этапа 3): в одном LRU вытеснение идёт по давности
 * записи, а долгоживущий процесс записывается ОДИН раз (на fork) — поток короткоживущих
 * процессов вымывал бы из LRU именно демонов, чьи потомки и нужны цепочкам. Поэтому:
 *   proc_live   — HASH, записи ЖИВЫХ процессов; удаляется только на выходе. Переполнение
 *                 считается (PC_FORK_FULL), не вытесняет никого.
 *   proc_exited — LRU_HASH, записи вышедших с exit_ts; живут, пока LRU не вытеснит, а
 *                 читатель отбрасывает старше TTL (exit_ts + TTL).
 *
 * Отдельный объект, а не часть syscall.bpf.c: bpf2go загружает коллекцию целиком, и
 * отказ верификатора на новых tp_btf-программах унёс бы за собой syscall-коллектор. Здесь
 * отказ означает «таблицы нет» — LineageTracker остаётся на старом пути.
 *
 * Не включает common.h (ни одна из его карт здесь не нужна).
 * Целевое ядро: 5.15+ с BTF (tp_btf, CO-RE).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "proctable.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef PROC_LIVE_ENTRIES
#define PROC_LIVE_ENTRIES 16384
#endif
#ifndef PROC_EXITED_ENTRIES
#define PROC_EXITED_ENTRIES 16384
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROC_LIVE_ENTRIES);
	__type(key, __u32);
	__type(value, struct proc_rec);
} proc_live SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROC_EXITED_ENTRIES);
	__type(key, __u32);
	__type(value, struct proc_rec);
} proc_exited SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PC_MAX);
	__type(key, __u32);
	__type(value, __u64);
} proc_table_counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&proc_table_counters, &idx);

	if (v)
		(*v)++;
}

/* Образ исполняемого файла: mm->exe_file->f_inode. У kernel thread mm == NULL — поля остаются 0. */
static __always_inline void fill_exe(struct proc_rec *rec, struct task_struct *task)
{
	struct file *f = BPF_CORE_READ(task, mm, exe_file);
	struct inode *in;

	if (!f)
		return;
	in = BPF_CORE_READ(f, f_inode);
	if (!in)
		return;
	rec->exe_ino = BPF_CORE_READ(in, i_ino);
	rec->exe_dev = BPF_CORE_READ(in, i_sb, s_dev);
}

static __always_inline void fill_from_task(struct proc_rec *rec, struct task_struct *task)
{
	rec->start_boottime = BPF_CORE_READ(task, start_boottime);
	rec->ppid = BPF_CORE_READ(task, real_parent, tgid);
	BPF_CORE_READ_STR_INTO(&rec->comm, task, comm);
	fill_exe(rec, task);
}

static __always_inline void set_filename(struct proc_rec *rec, const char *fname)
{
	long n;

	rec->filename[0] = 0;
	rec->flags &= ~PROC_FLAG_FNAME_TRUNC;
	if (!fname)
		return;
	n = bpf_probe_read_kernel_str(rec->filename, sizeof(rec->filename), fname);
	/* n — длина с NUL; n == размеру буфера значит, что путь не поместился */
	if (n >= (long)sizeof(rec->filename))
		rec->flags |= PROC_FLAG_FNAME_TRUNC;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(proc_fork, struct task_struct *parent, struct task_struct *child)
{
	struct proc_rec rec = {};
	__u32 tgid = BPF_CORE_READ(child, tgid);

	/* нить, а не процесс: tgid ≠ pid — запись не нужна */
	if (tgid != (__u32)BPF_CORE_READ(child, pid))
		return 0;

	fill_from_task(&rec, child);
	if (bpf_map_update_elem(&proc_live, &tgid, &rec, BPF_ANY))
		bump(PC_FORK_FULL);
	else
		bump(PC_FORK_OK);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(proc_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 tgid = BPF_CORE_READ(p, tgid);
	const char *fname = BPF_CORE_READ(bprm, filename);
	struct proc_rec *r = bpf_map_lookup_elem(&proc_live, &tgid);

	if (r) {
		/* start_boottime и ppid остаются от fork: exec — тот же процесс. Остальное — новое. */
		BPF_CORE_READ_STR_INTO(&r->comm, p, comm);
		fill_exe(r, p);
		set_filename(r, fname);
		r->flags |= PROC_FLAG_EXEC;
		bump(PC_EXEC_UPDATED);
		return 0;
	}

	{
		struct proc_rec rec = {};

		fill_from_task(&rec, p);
		set_filename(&rec, fname);
		rec.flags |= PROC_FLAG_EXEC;
		if (bpf_map_update_elem(&proc_live, &tgid, &rec, BPF_NOEXIST))
			bump(PC_EXEC_FULL);
		else
			bump(PC_EXEC_CREATED);
	}
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(proc_exit, struct task_struct *p)
{
	struct proc_rec copy;
	struct proc_rec *r;
	__u32 tgid = BPF_CORE_READ(p, tgid);

	/* выход нити — не выход процесса. Выход лидера при живых нитях помечает процесс
	 * вышедшим раньше времени; для цепочки предков это безвредно (запись читается из
	 * обеих карт), а лидер, умирающий раньше своих нитей, — редкость. */
	if (tgid != (__u32)BPF_CORE_READ(p, pid))
		return 0;

	r = bpf_map_lookup_elem(&proc_live, &tgid);
	if (!r) {
		bump(PC_EXIT_NOREC);
		return 0;
	}
	copy = *r;
	copy.exit_ts = bpf_ktime_get_ns();
	/* последнее имя: процесс мог переименоваться prctl(PR_SET_NAME) после exec */
	BPF_CORE_READ_STR_INTO(&copy.comm, p, comm);
	bpf_map_update_elem(&proc_exited, &tgid, &copy, BPF_ANY);
	bump(PC_EXITED_INSERT);
	bpf_map_delete_elem(&proc_live, &tgid);
	bump(PC_EXIT_MOVED);
	return 0;
}
