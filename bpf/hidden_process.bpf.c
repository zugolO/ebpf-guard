/*
 * hidden_process.bpf.c — hidden process detection for ebpf-guard.
 *
 * Uses the BPF task iterator (bpf_iter/task, kernel 5.8+) to enumerate
 * every task_struct in the kernel and output {tgid, pid, comm} tuples
 * via the seq_file interface. From userspace, the detector periodically
 * reads this output and diffs it against /proc enumeration — any PID
 * present in the kernel list but absent from /proc is a hidden process
 * (classic rootkit behaviour).
 *
 * Target: Linux kernel 5.8+
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * iter/task — called once for every task_struct in the system.
 * Output format (one line per task):
 *   <tgid> <pid> <comm>\n
 *
 * tgid: thread group ID (what userspace calls PID)
 * pid:  kernel thread ID (tid in userspace)
 * comm: task name (up to 15 chars + NUL)
 */
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (task == NULL)
		return 0;

	__u32 tgid = BPF_CORE_READ(task, tgid);
	__u32 pid  = BPF_CORE_READ(task, pid);
	char comm[16] = {};

	BPF_CORE_READ_STR_INTO(&comm, task, comm);

	BPF_SEQ_PRINTF(seq, "%u %u %s\n", tgid, pid, comm);
	return 0;
}
