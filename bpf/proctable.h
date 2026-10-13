/*
 * proctable.h — раскладка записи таблицы процессов в ядре (волна 8.5, P1).
 *
 * Общая для bpf/proctable.bpf.c и Go (internal/bpf/proctable.go): размер и смещения
 * проверяются _Static_assert здесь, а Go-сторож (TestW85_P1_RecordLayoutMatchesHeader)
 * читает ЭТОТ файл и сверяет свои константы — разошлись, красный тест.
 *
 * Запись живёт в двух картах (proctable.bpf.c): proc_live — процессы, которые ещё
 * не вышли, proc_exited — вышедшие (LRU), чтобы цепочка мс-процесса была читаема
 * после его смерти (nginx → bash → curl, bash уже мёртв).
 */
#ifndef __EG_PROCTABLE_H
#define __EG_PROCTABLE_H

#define PROC_COMM_LEN  16
#define PROC_FNAME_LEN 128

/* flags */
#define PROC_FLAG_EXEC        0x1  /* execve наблюдался: comm/filename/exe — после exec */
#define PROC_FLAG_FNAME_TRUNC 0x2  /* filename обрезан по PROC_FNAME_LEN-1 */
#define PROC_FLAG_SEEDED      0x4  /* запись из /proc при старте агента (до ядра), filename пуст */

struct proc_rec {
	__u64 start_boottime;            /* task->start_boottime, нс (то же, что /proc/<pid>/stat поле 22 в тиках) */
	__u64 exit_ts;                   /* bpf_ktime_get_ns() при выходе; 0 — жив */
	__u64 exe_ino;                   /* inode исполняемого файла (mm->exe_file) */
	__u32 ppid;                      /* tgid real_parent на момент fork (не меняется при reparent) */
	__u32 exe_dev;                   /* s_dev файловой системы exe */
	__u32 flags;
	__u32 pad;
	__u8  comm[PROC_COMM_LEN];       /* имя: после fork — родителя, после exec — нового, на выходе — последнее */
	__u8  filename[PROC_FNAME_LEN];  /* bprm->filename ПОСЛЕДНЕГО exec (для шебанг-скрипта — путь скрипта) */
};

#define PROC_REC_SIZE 184
#define PROC_REC_START_OFFSET    0
#define PROC_REC_EXIT_TS_OFFSET  8
#define PROC_REC_EXE_INO_OFFSET  16
#define PROC_REC_PPID_OFFSET     24
#define PROC_REC_EXE_DEV_OFFSET  28
#define PROC_REC_FLAGS_OFFSET    32
#define PROC_REC_COMM_OFFSET     40
#define PROC_REC_FILENAME_OFFSET 56

_Static_assert(sizeof(struct proc_rec) == PROC_REC_SIZE,
	       "struct proc_rec size changed: update PROC_REC_SIZE and internal/bpf/proctable.go");
_Static_assert(__builtin_offsetof(struct proc_rec, exit_ts) == PROC_REC_EXIT_TS_OFFSET, "proc_rec.exit_ts moved");
_Static_assert(__builtin_offsetof(struct proc_rec, exe_ino) == PROC_REC_EXE_INO_OFFSET, "proc_rec.exe_ino moved");
_Static_assert(__builtin_offsetof(struct proc_rec, ppid) == PROC_REC_PPID_OFFSET, "proc_rec.ppid moved");
_Static_assert(__builtin_offsetof(struct proc_rec, exe_dev) == PROC_REC_EXE_DEV_OFFSET, "proc_rec.exe_dev moved");
_Static_assert(__builtin_offsetof(struct proc_rec, flags) == PROC_REC_FLAGS_OFFSET, "proc_rec.flags moved");
_Static_assert(__builtin_offsetof(struct proc_rec, comm) == PROC_REC_COMM_OFFSET, "proc_rec.comm moved");
_Static_assert(__builtin_offsetof(struct proc_rec, filename) == PROC_REC_FILENAME_OFFSET, "proc_rec.filename moved");

/* Счётчики исходов хуков (PERCPU_ARRAY proc_table_counters); порядок = Go (procTableCounterNames). */
enum proc_counter {
	PC_FORK_OK = 0,        /* запись создана на fork */
	PC_FORK_FULL,          /* proc_live полна — запись потеряна */
	PC_EXEC_UPDATED,       /* exec обновил запись fork */
	PC_EXEC_CREATED,       /* записи fork не было (процесс старше агента/потеряна) — создана на exec */
	PC_EXEC_FULL,          /* exec без записи и proc_live полна */
	PC_EXIT_MOVED,         /* запись переехала из proc_live в proc_exited */
	PC_EXIT_NOREC,         /* на выходе записи в proc_live нет */
	PC_EXITED_INSERT,      /* вставок в proc_exited (LRU вытесняет самые давние сам) */
	PC_MAX
};

#endif /* __EG_PROCTABLE_H */
