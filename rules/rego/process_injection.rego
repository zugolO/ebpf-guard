# Process Injection detection rules (Rego)
# MITRE ATT&CK: T1055 — Process Injection
# Covers ptrace, memfd fileless execution, /proc/PID/mem write, LD_PRELOAD hijacking.

package ebpf_guard.process_injection

# Rule: ptrace attach to another process
# MITRE ATT&CK: T1055.008 — Process Injection: ptrace System Calls
rules[{"rule_id": "ptrace_injection", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1055.008", "matched": true}] {
	input.event.syscall
	input.event.syscall.nr == 101   # __NR_ptrace
	not is_debugger(input.comm)
	msg := sprintf("ptrace syscall from non-debugger process %s (pid=%d) — potential process injection T1055.008", [input.comm, input.pid])
}

# Rule: memfd_create — anonymous RAM-backed file creation (fileless staging)
# MITRE ATT&CK: T1055.002 — Process Injection: Portable Executable Injection
rules[{"rule_id": "memfd_fileless_staging", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1055.002", "matched": true}] {
	input.event.syscall
	input.event.syscall.nr == 319   # __NR_memfd_create
	msg := sprintf("memfd_create called by %s (pid=%d) — fileless payload staging T1055.002", [input.comm, input.pid])
}

# Rule: fexecve — execute file by descriptor (canonical fileless execution step)
# MITRE ATT&CK: T1055.002
rules[{"rule_id": "fexecve_fileless_exec", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1055.002", "matched": true}] {
	input.event.syscall
	input.event.syscall.nr == 322   # __NR_execveat (fexecve uses AT_EMPTY_PATH)
	msg := sprintf("fexecve/execveat called by %s (pid=%d) — potential fileless execution T1055.002", [input.comm, input.pid])
}

# Rule: /proc/<pid>/mem write — direct memory injection without ptrace
# MITRE ATT&CK: T1055.009 — Process Injection: Proc Memory
rules[{"rule_id": "proc_mem_write", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1055.009", "matched": true}] {
	input.event.file
	regex.match("/proc/[0-9]+/mem", input.event.file.filename)
	msg := sprintf("Direct /proc memory write to %s by %s (pid=%d) — process injection T1055.009", [input.event.file.filename, input.comm, input.pid])
}

# Rule: LD_PRELOAD persistent hijack via /etc/ld.so.preload
# MITRE ATT&CK: T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking
rules[{"rule_id": "ld_preload_hijack", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1574.006", "matched": true}] {
	input.event.file
	input.event.file.filename == "/etc/ld.so.preload"
	msg := sprintf("/etc/ld.so.preload modified by %s (pid=%d) — dynamic linker hijack T1574.006", [input.comm, input.pid])
}

# Rule: Malicious .so staged in /dev/shm
# MITRE ATT&CK: T1055 + T1574.006
rules[{"rule_id": "devshm_so_staging", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1055", "matched": true}] {
	input.event.file
	startswith(input.event.file.filename, "/dev/shm/")
	endswith(input.event.file.filename, ".so")
	msg := sprintf("Shared object staged in /dev/shm: %s by %s (pid=%d) — injection staging T1055/T1574.006", [input.event.file.filename, input.comm, input.pid])
}

# Helper: Debuggers that legitimately use ptrace
is_debugger(comm) {
	comm == "gdb"
}

is_debugger(comm) {
	comm == "strace"
}

is_debugger(comm) {
	comm == "ltrace"
}

is_debugger(comm) {
	comm == "perf"
}

is_debugger(comm) {
	comm == "rr"
}

is_debugger(comm) {
	comm == "valgrind"
}

is_debugger(comm) {
	comm == "ptrace"
}

is_debugger(comm) {
	startswith(comm, "java")   # JVM uses ptrace for JIT profiling
}
