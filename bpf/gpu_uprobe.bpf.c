/*
 * gpu_uprobe.bpf.c - eBPF uprobe programs for CUDA/GPU memory monitoring.
 *
 * Attaches to CUDA Driver API (libcuda.so) and CUDA Runtime API (libcudart.so)
 * to intercept GPU memory operations and detect data exfiltration via Device-to-Host
 * copies from AI/ML training workloads.
 *
 * Monitored functions:
 *   libcuda.so:   cuMemAlloc_v2, cuMemFree_v2,
 *                 cuMemcpyDtoH_v2, cuMemcpyDtoHAsync_v2,
 *                 cuMemcpyHtoD_v2, cuMemcpyHtoDAsync_v2
 *   libcudart.so: cudaMalloc, cudaFree, cudaMemcpy (DtoH/HtoD kinds only)
 *
 * Target: Linux kernel 5.15+ with BTF/CO-RE support.
 * Requires: CAP_SYS_PTRACE for uprobe attachment.
 *
 * Data exfiltration model:
 *   Training data resides in GPU device memory. To exfiltrate it, an attacker must
 *   copy it to host memory via cuMemcpyDtoH or cudaMemcpy(DtoH). Monitoring
 *   these calls — especially large or repeated ones from unexpected processes —
 *   is the primary detection signal.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/* GPU-specific event type */
#define EVENT_TYPE_GPU 10

/* GPU operation codes — must match pkg/types/event.go GPUOpType constants */
#define GPU_OP_ALLOC          0  /* cuMemAlloc_v2 / cudaMalloc               */
#define GPU_OP_FREE           1  /* cuMemFree_v2 / cudaFree                  */
#define GPU_OP_MEMCPY_HTOD    2  /* Host → Device                            */
#define GPU_OP_MEMCPY_DTOH    3  /* Device → Host  (exfiltration signal)     */
#define GPU_OP_MEMCPY_DTOD    4  /* Device → Device                          */
#define GPU_OP_KERNEL_LAUNCH  5  /* cuLaunchKernel                           */

/* cudaMemcpyKind constants from CUDA headers */
#define CUDA_MEMCPY_HOST_TO_HOST   0
#define CUDA_MEMCPY_HOST_TO_DEVICE 1
#define CUDA_MEMCPY_DEVICE_TO_HOST 2
#define CUDA_MEMCPY_DEVICE_TO_DEVICE 3

/*
 * GPU event structure — layout must match GPUEventRaw in internal/collector/gpu.go.
 * Uses __attribute__((packed)) to avoid compiler padding; binary.Read in Go
 * reads the bytes sequentially and handles unaligned fields correctly.
 */
struct gpu_event {
	__u32 type;
	__u64 timestamp;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u8  comm[COMM_LEN];
	__u8  parent_comm[COMM_LEN];
	__u8  op;        /* GPU_OP_* */
	__u64 dev_ptr;   /* GPU device memory address                     */
	__u64 host_ptr;  /* Host memory address (memcpy ops only)         */
	__u64 size;      /* Bytes allocated, freed, or transferred        */
} __attribute__((packed));

/* Ring buffer for GPU events (256KB — sufficient for ~3000 events/s burst) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} gpu_events SEC(".maps");

/*
 * Context saved between cuMemAlloc_v2 entry and return probes.
 * The allocated device pointer is an output parameter (*dptr), so we cannot
 * read it until the function returns.
 */
struct gpu_alloc_ctx {
	__u64 dptr_ptr; /* address of the CUdeviceptr* output parameter  */
	__u64 size;     /* allocation size in bytes                       */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);                  /* pid_tgid */
	__type(value, struct gpu_alloc_ctx);
} gpu_alloc_contexts SEC(".maps");

/* ── helpers ──────────────────────────────────────────────────────────── */

static __always_inline void fill_gpu_process_info(struct gpu_event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid  = bpf_get_current_uid_gid();
	struct task_struct *task;
	struct task_struct *parent;

	e->pid  = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->uid  = (__u32)uid_gid;
	e->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	task   = (struct task_struct *)bpf_get_current_task();
	parent = task->real_parent;
	if (parent) {
		e->ppid = parent->tgid;
		bpf_probe_read_kernel(&e->parent_comm, sizeof(e->parent_comm),
			&parent->comm);
	} else {
		e->ppid = 0;
		__builtin_memset(&e->parent_comm, 0, sizeof(e->parent_comm));
	}
}

static __always_inline struct gpu_event *reserve_gpu_event(__u8 op)
{
	struct gpu_event *e;

	e = bpf_ringbuf_reserve(&gpu_events, sizeof(struct gpu_event), 0);
	if (!e)
		return NULL;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_TYPE_GPU;
	e->op   = op;
	fill_gpu_process_info(e);
	return e;
}

/* ── cuMemAlloc_v2 ────────────────────────────────────────────────────── */
/*
 * CUresult cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize)
 * x86_64: rdi=dptr, rsi=bytesize
 */
SEC("uprobe/cuMemAlloc_v2")
int trace_cu_mem_alloc_entry(struct pt_regs *ctx)
{
	struct gpu_alloc_ctx alloc_ctx = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

#if defined(__TARGET_ARCH_x86_64)
	alloc_ctx.dptr_ptr = PT_REGS_PARM1(ctx);
	alloc_ctx.size     = PT_REGS_PARM2(ctx);
#elif defined(__TARGET_ARCH_arm64)
	alloc_ctx.dptr_ptr = PT_REGS_PARM1(ctx);
	alloc_ctx.size     = PT_REGS_PARM2(ctx);
#else
	alloc_ctx.dptr_ptr = ctx->di;
	alloc_ctx.size     = ctx->si;
#endif

	bpf_map_update_elem(&gpu_alloc_contexts, &pid_tgid, &alloc_ctx, BPF_ANY);
	return 0;
}

SEC("uretprobe/cuMemAlloc_v2")
int trace_cu_mem_alloc_ret(struct pt_regs *ctx)
{
	struct gpu_alloc_ctx *alloc_ctx;
	struct gpu_event *e;
	__u64 pid_tgid;
	__u64 dev_ptr = 0;

	/* Only emit on success (CUresult == 0) */
	if ((int)PT_REGS_RC(ctx) != 0)
		goto cleanup;

	pid_tgid  = bpf_get_current_pid_tgid();
	alloc_ctx = bpf_map_lookup_elem(&gpu_alloc_contexts, &pid_tgid);
	if (!alloc_ctx)
		return 0;

	/* Read the allocated device pointer from *dptr */
	bpf_probe_read_user(&dev_ptr, sizeof(dev_ptr), (void *)alloc_ctx->dptr_ptr);

	e = reserve_gpu_event(GPU_OP_ALLOC);
	if (e) {
		e->dev_ptr  = dev_ptr;
		e->host_ptr = 0;
		e->size     = alloc_ctx->size;
		bpf_ringbuf_submit(e, 0);
	}

cleanup:
	pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&gpu_alloc_contexts, &pid_tgid);
	return 0;
}

/* ── cuMemFree_v2 ─────────────────────────────────────────────────────── */
/*
 * CUresult cuMemFree_v2(CUdeviceptr dptr)
 * x86_64: rdi=dptr
 */
SEC("uprobe/cuMemFree_v2")
int trace_cu_mem_free(struct pt_regs *ctx)
{
	struct gpu_event *e;

	e = reserve_gpu_event(GPU_OP_FREE);
	if (!e)
		return 0;

#if defined(__TARGET_ARCH_x86_64)
	e->dev_ptr = PT_REGS_PARM1(ctx);
#elif defined(__TARGET_ARCH_arm64)
	e->dev_ptr = PT_REGS_PARM1(ctx);
#else
	e->dev_ptr = ctx->di;
#endif
	e->host_ptr = 0;
	e->size     = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── cuMemcpyDtoH_v2 (Device → Host, synchronous) ────────────────────── */
/*
 * CUresult cuMemcpyDtoH_v2(void *dstHost, CUdeviceptr srcDevice, size_t ByteCount)
 * x86_64: rdi=dstHost, rsi=srcDevice, rdx=ByteCount
 */
SEC("uprobe/cuMemcpyDtoH_v2")
int trace_cu_memcpy_dtoh(struct pt_regs *ctx)
{
	struct gpu_event *e;

	e = reserve_gpu_event(GPU_OP_MEMCPY_DTOH);
	if (!e)
		return 0;

#if defined(__TARGET_ARCH_x86_64)
	e->host_ptr = PT_REGS_PARM1(ctx);
	e->dev_ptr  = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
	e->host_ptr = PT_REGS_PARM1(ctx);
	e->dev_ptr  = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#else
	e->host_ptr = ctx->di;
	e->dev_ptr  = ctx->si;
	e->size     = ctx->dx;
#endif

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── cuMemcpyDtoHAsync_v2 (Device → Host, asynchronous) ──────────────── */
/*
 * CUresult cuMemcpyDtoHAsync_v2(void *dstHost, CUdeviceptr srcDevice,
 *                               size_t ByteCount, CUstream hStream)
 * x86_64: rdi=dstHost, rsi=srcDevice, rdx=ByteCount, rcx=hStream
 */
SEC("uprobe/cuMemcpyDtoHAsync_v2")
int trace_cu_memcpy_dtoh_async(struct pt_regs *ctx)
{
	struct gpu_event *e;

	e = reserve_gpu_event(GPU_OP_MEMCPY_DTOH);
	if (!e)
		return 0;

#if defined(__TARGET_ARCH_x86_64)
	e->host_ptr = PT_REGS_PARM1(ctx);
	e->dev_ptr  = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
	e->host_ptr = PT_REGS_PARM1(ctx);
	e->dev_ptr  = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#else
	e->host_ptr = ctx->di;
	e->dev_ptr  = ctx->si;
	e->size     = ctx->dx;
#endif

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── cuMemcpyHtoD_v2 (Host → Device, synchronous) ────────────────────── */
/*
 * CUresult cuMemcpyHtoD_v2(CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount)
 * x86_64: rdi=dstDevice, rsi=srcHost, rdx=ByteCount
 */
SEC("uprobe/cuMemcpyHtoD_v2")
int trace_cu_memcpy_htod(struct pt_regs *ctx)
{
	struct gpu_event *e;

	e = reserve_gpu_event(GPU_OP_MEMCPY_HTOD);
	if (!e)
		return 0;

#if defined(__TARGET_ARCH_x86_64)
	e->dev_ptr  = PT_REGS_PARM1(ctx);
	e->host_ptr = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
	e->dev_ptr  = PT_REGS_PARM1(ctx);
	e->host_ptr = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#else
	e->dev_ptr  = ctx->di;
	e->host_ptr = ctx->si;
	e->size     = ctx->dx;
#endif

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── cuMemcpyHtoDAsync_v2 (Host → Device, asynchronous) ──────────────── */
/*
 * CUresult cuMemcpyHtoDAsync_v2(CUdeviceptr dstDevice, const void *srcHost,
 *                               size_t ByteCount, CUstream hStream)
 */
SEC("uprobe/cuMemcpyHtoDAsync_v2")
int trace_cu_memcpy_htod_async(struct pt_regs *ctx)
{
	struct gpu_event *e;

	e = reserve_gpu_event(GPU_OP_MEMCPY_HTOD);
	if (!e)
		return 0;

#if defined(__TARGET_ARCH_x86_64)
	e->dev_ptr  = PT_REGS_PARM1(ctx);
	e->host_ptr = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
	e->dev_ptr  = PT_REGS_PARM1(ctx);
	e->host_ptr = PT_REGS_PARM2(ctx);
	e->size     = PT_REGS_PARM3(ctx);
#else
	e->dev_ptr  = ctx->di;
	e->host_ptr = ctx->si;
	e->size     = ctx->dx;
#endif

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── cudaMalloc (CUDA Runtime — entry + return) ───────────────────────── */
/*
 * cudaError_t cudaMalloc(void **devPtr, size_t size)
 * x86_64: rdi=devPtr, rsi=size
 */
SEC("uprobe/cudaMalloc")
int trace_cuda_malloc_entry(struct pt_regs *ctx)
{
	struct gpu_alloc_ctx alloc_ctx = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

#if defined(__TARGET_ARCH_x86_64)
	alloc_ctx.dptr_ptr = PT_REGS_PARM1(ctx);
	alloc_ctx.size     = PT_REGS_PARM2(ctx);
#else
	alloc_ctx.dptr_ptr = ctx->di;
	alloc_ctx.size     = ctx->si;
#endif

	bpf_map_update_elem(&gpu_alloc_contexts, &pid_tgid, &alloc_ctx, BPF_ANY);
	return 0;
}

SEC("uretprobe/cudaMalloc")
int trace_cuda_malloc_ret(struct pt_regs *ctx)
{
	struct gpu_alloc_ctx *alloc_ctx;
	struct gpu_event *e;
	__u64 pid_tgid;
	__u64 dev_ptr = 0;

	if ((int)PT_REGS_RC(ctx) != 0)
		goto cleanup;

	pid_tgid  = bpf_get_current_pid_tgid();
	alloc_ctx = bpf_map_lookup_elem(&gpu_alloc_contexts, &pid_tgid);
	if (!alloc_ctx)
		return 0;

	bpf_probe_read_user(&dev_ptr, sizeof(dev_ptr), (void *)alloc_ctx->dptr_ptr);

	e = reserve_gpu_event(GPU_OP_ALLOC);
	if (e) {
		e->dev_ptr  = dev_ptr;
		e->host_ptr = 0;
		e->size     = alloc_ctx->size;
		bpf_ringbuf_submit(e, 0);
	}

cleanup:
	pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&gpu_alloc_contexts, &pid_tgid);
	return 0;
}

/* ── cudaFree (CUDA Runtime) ──────────────────────────────────────────── */
/*
 * cudaError_t cudaFree(void *devPtr)
 * x86_64: rdi=devPtr
 */
SEC("uprobe/cudaFree")
int trace_cuda_free(struct pt_regs *ctx)
{
	struct gpu_event *e;

	e = reserve_gpu_event(GPU_OP_FREE);
	if (!e)
		return 0;

#if defined(__TARGET_ARCH_x86_64)
	e->dev_ptr = PT_REGS_PARM1(ctx);
#else
	e->dev_ptr = ctx->di;
#endif
	e->host_ptr = 0;
	e->size     = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── cudaMemcpy (CUDA Runtime — direction via 'kind' parameter) ───────── */
/*
 * cudaError_t cudaMemcpy(void *dst, const void *src, size_t count, cudaMemcpyKind kind)
 * x86_64: rdi=dst, rsi=src, rdx=count, rcx=kind
 *
 * Only DtoH (kind==2) and HtoD (kind==1) are emitted; HtoH and DtoD are
 * not interesting for security monitoring.
 */
SEC("uprobe/cudaMemcpy")
int trace_cuda_memcpy(struct pt_regs *ctx)
{
	struct gpu_event *e;
	__u64 dst, src, count;
	int kind;

#if defined(__TARGET_ARCH_x86_64)
	dst   = PT_REGS_PARM1(ctx);
	src   = PT_REGS_PARM2(ctx);
	count = PT_REGS_PARM3(ctx);
	kind  = (int)PT_REGS_PARM4(ctx);
#else
	dst   = ctx->di;
	src   = ctx->si;
	count = ctx->dx;
	kind  = (int)ctx->cx;
#endif

	if (kind == CUDA_MEMCPY_DEVICE_TO_HOST) {
		e = reserve_gpu_event(GPU_OP_MEMCPY_DTOH);
		if (!e)
			return 0;
		e->host_ptr = dst;
		e->dev_ptr  = src;
		e->size     = count;
		bpf_ringbuf_submit(e, 0);
	} else if (kind == CUDA_MEMCPY_HOST_TO_DEVICE) {
		e = reserve_gpu_event(GPU_OP_MEMCPY_HTOD);
		if (!e)
			return 0;
		e->dev_ptr  = dst;
		e->host_ptr = src;
		e->size     = count;
		bpf_ringbuf_submit(e, 0);
	}
	/* HtoH and DtoD are ignored */
	return 0;
}

/* ── cuLaunchKernel ───────────────────────────────────────────────────── */
/*
 * CUresult cuLaunchKernel(CUfunction f, unsigned int gridDimX, ...)
 * We only record that a kernel was launched (not the full argument list).
 * x86_64: rdi=f (CUfunction handle)
 */
SEC("uprobe/cuLaunchKernel")
int trace_cu_launch_kernel(struct pt_regs *ctx)
{
	struct gpu_event *e;

	e = reserve_gpu_event(GPU_OP_KERNEL_LAUNCH);
	if (!e)
		return 0;

	/* Store the CUfunction handle in dev_ptr for correlation */
#if defined(__TARGET_ARCH_x86_64)
	e->dev_ptr = PT_REGS_PARM1(ctx);
#else
	e->dev_ptr = ctx->di;
#endif
	e->host_ptr = 0;
	e->size     = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
