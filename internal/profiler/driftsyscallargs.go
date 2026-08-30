package profiler

import (
	"strconv"
	"strings"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// This file gives the drift baseline a discriminator for the syscalls that
// carry no proc.args.
//
// Measurement №6.0 (2026-08-29) left drift_dangerous_syscall with 416
// suppressed matches and zero alerts. The cause was not the path collapse that
// broke the exec rule (see normalizeDriftPath) but a second, independent one:
// for ptrace/mount/unshare/setns/bpf/... the collector attaches no proc.args,
// so driftSignatureTarget reduced the whole event to a decimal syscall number.
// One mount during learning made every later mount by that workload "known"
// forever — and "every later mount" includes the container escape the rule is
// named after.
//
// The register arguments were available the whole time. bpf/syscall.bpf.c
// copies ctx->args into the event on sys_enter and restores them from the
// syscall_args map on sys_exit; internal/bpf/events.go carries them into
// types.SyscallEvent.Args; the rule engine already exposes them as arg0..arg5.
// They simply were not read by the profiler.
//
// Only SCALAR arguments are usable. mount(2)'s source/target/filesystemtype
// are pointers into the calling process's address space, and by the time a
// ring-buffer record is dequeued in userspace that memory is gone (and the
// process may be too). Reading those strings requires bpf_probe_read_user_str
// on sys_enter, i.e. a BPF-side change and a `make generate` run — deliberately
// out of scope here. Syscalls whose every argument is a pointer therefore get
// no discriminator at all and are better served by a class: threat rule that
// alerts on occurrence; see rules/drift-rules.yaml.

// driftSyscallArgSpec describes how to render the semantically meaningful
// arguments of one syscall into a stable signature fragment.
type driftSyscallArgSpec struct {
	// name is the syscall's name, so a signature reads
	// "165|mount=MS_BIND|MS_REC" rather than "165|4096".
	name string
	// format renders the meaningful arguments. It is only called when at
	// least one register argument is non-zero; see driftFormatSyscallArgs.
	format func(args [6]uint64) string
}

// driftSyscallArgUnknown is the fragment used when a syscall that should carry
// arguments arrives with all six registers zero. That happens on the sys_exit
// tracepoint when the syscall_args map missed (it is bounded and records
// MAP_FULL_IDX_SYSCALL_ARGS when full), and an all-zero read must not be
// mistaken for a real zero-valued argument: bpf(0, ...) is BPF_MAP_CREATE, a
// genuine escape primitive, and learning it from a dropped map entry would
// suppress the real thing.
//
// The cost of the guard is that a genuinely all-zero call — ptrace(PTRACE_TRACEME,
// 0, 0, 0) is the only realistic one — shares this fragment with lost
// arguments. Both are rare, and PTRACE_TRACEME stays distinct from
// PTRACE_ATTACH either way, which is the distinction that matters.
const driftSyscallArgUnknown = "?"

// driftFormatSyscallArgs renders spec's arguments, guarding the all-zero case.
func driftFormatSyscallArgs(spec driftSyscallArgSpec, args [6]uint64) string {
	allZero := true
	for _, a := range args {
		if a != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return driftSyscallArgUnknown
	}
	return spec.format(args)
}

// driftSyscallArgSpecs maps x86_64 syscall numbers to their discriminator.
// The set is exactly the syscalls named by class: drift rules that match on
// `nr` — adding a syscall to such a rule without adding it here silently
// leaves that syscall with a bare-number signature, which is the defect this
// file exists to fix.
var driftSyscallArgSpecs = map[int64]driftSyscallArgSpec{
	// ptrace(request, pid, addr, data): request is the operation. Attaching to
	// another process (ATTACH/SEIZE) is a different act from reading one's own
	// registers, and only the number tells them apart.
	101: {"ptrace", func(a [6]uint64) string { return ptraceRequestName(a[0]) }},
	// mount(source, target, filesystemtype, mountflags, data): only mountflags
	// is a scalar. MS_BIND (a bind mount of the host filesystem) and
	// MS_REMOUNT|MS_RDONLY (dropping a read-only protection) are the escape
	// shapes; the runtime's own namespace setup uses different flag sets.
	165: {"mount", func(a [6]uint64) string { return mountFlagNames(a[3]) }},
	// umount2(target, flags)
	166: {"umount2", func(a [6]uint64) string { return umount2FlagNames(a[1]) }},
	// unshare(flags): CLONE_NEWUSER|CLONE_NEWNS is the classic unprivileged
	// container-escape prelude and must not be learnable from a CLONE_NEWNS-only
	// baseline.
	272: {"unshare", func(a [6]uint64) string { return cloneNamespaceFlagNames(a[0]) }},
	// setns(fd, nstype): the target namespace type. Entering a PID or network
	// namespace is the interesting case; fd itself is not stable.
	308: {"setns", func(a [6]uint64) string { return cloneNamespaceFlagNames(a[1]) }},
	// bpf(cmd, attr, size): cmd separates loading a program from looking up a
	// map. types.BPFCmdName is the existing name table.
	321: {"bpf", func(a [6]uint64) string { return types.BPFCmdName(uint32(a[0])) }},
	// kexec_load(entry, nr_segments, segments, flags)
	246: {"kexec_load", func(a [6]uint64) string { return "flags=0x" + strconv.FormatUint(a[3], 16) }},
	// perf_event_open(attr, pid, cpu, group_fd, flags): pid == -1 means
	// system-wide profiling, which is a different capability from profiling
	// one's own process, so it belongs in the signature.
	298: {"perf_event_open", func(a [6]uint64) string {
		scope := "pid"
		if int64(a[1]) == -1 {
			scope = "system_wide"
		}
		return scope + ",flags=0x" + strconv.FormatUint(a[4], 16)
	}},
	// pivot_root(new_root, put_old), add_key and request_key are deliberately
	// absent: every argument they carry is a userspace pointer, so no
	// discriminator exists without reading the strings in BPF. They are handled
	// as class: threat rules instead — see rules/drift-rules.yaml.
}

// ptraceRequestName maps a ptrace(2) request to its name, falling back to the
// number so an unmapped request still produces a distinct signature.
func ptraceRequestName(req uint64) string {
	switch req {
	case 0:
		return "PTRACE_TRACEME"
	case 1:
		return "PTRACE_PEEKTEXT"
	case 2:
		return "PTRACE_PEEKDATA"
	case 3:
		return "PTRACE_PEEKUSER"
	case 4:
		return "PTRACE_POKETEXT"
	case 5:
		return "PTRACE_POKEDATA"
	case 6:
		return "PTRACE_POKEUSER"
	case 7:
		return "PTRACE_CONT"
	case 8:
		return "PTRACE_KILL"
	case 9:
		return "PTRACE_SINGLESTEP"
	case 12:
		return "PTRACE_GETREGS"
	case 13:
		return "PTRACE_SETREGS"
	case 16:
		return "PTRACE_ATTACH"
	case 17:
		return "PTRACE_DETACH"
	case 24:
		return "PTRACE_SYSCALL"
	case 0x4200:
		return "PTRACE_SETOPTIONS"
	case 0x4206:
		return "PTRACE_SEIZE"
	case 0x4207:
		return "PTRACE_INTERRUPT"
	default:
		return "PTRACE_REQ_" + strconv.FormatUint(req, 10)
	}
}

// namedFlag pairs a flag bit with its name for flagNames.
type namedFlag struct {
	bit  uint64
	name string
}

// flagNames renders the set bits of v using table, in table order, joined by
// "|". Bits with no entry in table are appended as a single hex remainder so
// two different unknown flag sets never collapse into one signature. A zero
// value renders as "0".
func flagNames(v uint64, table []namedFlag) string {
	if v == 0 {
		return "0"
	}
	var parts []string
	rest := v
	for _, f := range table {
		if v&f.bit == f.bit {
			parts = append(parts, f.name)
			rest &^= f.bit
		}
	}
	if rest != 0 {
		parts = append(parts, "0x"+strconv.FormatUint(rest, 16))
	}
	return strings.Join(parts, "|")
}

// cloneNamespaceFlags covers the CLONE_NEW* namespace bits shared by
// unshare(2) and setns(2).
var cloneNamespaceFlags = []namedFlag{
	{0x00000080, "CLONE_NEWTIME"},
	{0x00020000, "CLONE_NEWNS"},
	{0x02000000, "CLONE_NEWCGROUP"},
	{0x04000000, "CLONE_NEWUTS"},
	{0x08000000, "CLONE_NEWIPC"},
	{0x10000000, "CLONE_NEWUSER"},
	{0x20000000, "CLONE_NEWPID"},
	{0x40000000, "CLONE_NEWNET"},
}

func cloneNamespaceFlagNames(v uint64) string { return flagNames(v, cloneNamespaceFlags) }

// mountFlags covers the mount(2) mountflags bits that change what a mount
// means for security. MS_MGC_VAL (0xC0ED0000), the legacy magic prefix, is
// masked off first so glibc callers that still set it do not produce a
// separate signature from those that do not.
var mountFlags = []namedFlag{
	{1 << 0, "MS_RDONLY"},
	{1 << 1, "MS_NOSUID"},
	{1 << 2, "MS_NODEV"},
	{1 << 3, "MS_NOEXEC"},
	{1 << 5, "MS_REMOUNT"},
	{1 << 12, "MS_BIND"},
	{1 << 13, "MS_MOVE"},
	{1 << 14, "MS_REC"},
	{1 << 18, "MS_PRIVATE"},
	{1 << 19, "MS_SLAVE"},
	{1 << 20, "MS_SHARED"},
}

const msMgcValMask = 0xC0ED0000

func mountFlagNames(v uint64) string {
	if v&0xFFFF0000 == msMgcValMask {
		v &^= msMgcValMask
	}
	return flagNames(v, mountFlags)
}

var umount2Flags = []namedFlag{
	{1 << 0, "MNT_FORCE"},
	{1 << 1, "MNT_DETACH"},
	{1 << 2, "MNT_EXPIRE"},
	{1 << 3, "UMOUNT_NOFOLLOW"},
}

func umount2FlagNames(v uint64) string { return flagNames(v, umount2Flags) }

// DriftSyscallHasArgSpec reports whether nr has a discriminating argument spec.
//
// Exported for the rule-coverage gate in internal/correlator: a class: drift
// rule that matches on a syscall number with no spec here has a signature of
// exactly one value per workload, so the first such call during learning
// silences the rule for that workload permanently. That is not a tuning
// mistake an operator can see — it looks identical to a quiet host — so it is
// checked by a test rather than left to review.
func DriftSyscallHasArgSpec(nr int64) bool {
	_, ok := driftSyscallArgSpecs[nr]
	return ok
}
