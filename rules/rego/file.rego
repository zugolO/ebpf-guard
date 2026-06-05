# File access detection rules
# Detects sensitive file access, credential theft, and configuration tampering

package ebpf_guard.file

# Rule: Access to /etc/shadow
# MITRE ATT&CK: T1003 - OS Credential Dumping
rules[{"rule_id": "shadow_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1003", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/etc/shadow")
	msg := sprintf("Access to /etc/shadow by %s (pid=%d)", [input.comm, input.pid])
}

# Rule: Access to /etc/passwd (read is normal, write is suspicious)
# MITRE ATT&CK: T1136 - Create Account
rules[{"rule_id": "passwd_write", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1136", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/etc/passwd")
	input.event.file.op == 2  # write
	msg := sprintf("Write to /etc/passwd by %s (pid=%d)", [input.comm, input.pid])
}

# Rule: Access to /etc/sudoers
# MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism
rules[{"rule_id": "sudoers_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1548", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/etc/sudoers")
	input.event.file.op == 2  # write
	msg := sprintf("Modification of sudoers by %s (pid=%d)", [input.comm, input.pid])
}

# Rule: SSH authorized_keys modification
# MITRE ATT&CK: T1098 - Account Manipulation
rules[{"rule_id": "authorized_keys_modify", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1098", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "authorized_keys")
	input.event.file.op == 2  # write
	msg := sprintf("SSH authorized_keys modified by %s (pid=%d): %s", [input.comm, input.pid, input.event.file.filename])
}

# Rule: SSH private key access
# MITRE ATT&CK: T1552 - Unsecured Credentials
rules[{"rule_id": "ssh_key_read", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1552", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, ".ssh/")
	contains(input.event.file.filename, "id_")
	not contains(input.event.file.filename, ".pub")  # Public keys are less sensitive
	msg := sprintf("SSH private key accessed by %s (pid=%d): %s", [input.comm, input.pid, input.event.file.filename])
}

# Rule: Kubernetes service account token access
# MITRE ATT&CK: T1552 - Unsecured Credentials
rules[{"rule_id": "k8s_token_access", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1552", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/var/run/secrets/kubernetes.io/serviceaccount")
	not is_kubernetes_component(input.comm)
	msg := sprintf("K8s service account token accessed by non-k8s process %s (pid=%d)", [input.comm, input.pid])
}

# Rule: Docker socket access
# MITRE ATT&CK: T1610 - Deploy Container
rules[{"rule_id": "docker_socket_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1610", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/var/run/docker.sock")
	not is_docker_component(input.comm)
	msg := sprintf("Docker socket accessed by %s (pid=%d) - potential container escape", [input.comm, input.pid])
}

# Rule: Containerd socket access
# MITRE ATT&CK: T1610 - Deploy Container
rules[{"rule_id": "containerd_socket_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1610", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/run/containerd")
	input.event.file.op == 0  # open
	not is_containerd_component(input.comm)
	msg := sprintf("Containerd socket accessed by %s (pid=%d) - potential container escape", [input.comm, input.pid])
}

# Rule: CRI-O socket access
# MITRE ATT&CK: T1610 - Deploy Container
rules[{"rule_id": "crio_socket_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1610", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/var/run/crio")
	not is_crio_component(input.comm)
	msg := sprintf("CRI-O socket accessed by %s (pid=%d) - potential container escape", [input.comm, input.pid])
}

# Rule: /proc filesystem enumeration (reconnaissance)
# MITRE ATT&CK: T1082 - System Information Discovery
rules[{"rule_id": "proc_enumeration", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1082", "matched": true}] {
	input.event.file
	startswith(input.event.file.filename, "/proc/")
	contains(input.event.file.filename, "/exe")
	is_shell(input.comm)
	msg := sprintf("Process enumeration via /proc by %s (pid=%d)", [input.comm, input.pid])
}

# Rule: Kernel module access
# MITRE ATT&CK: T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions
rules[{"rule_id": "kernel_module_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1547.006", "matched": true}] {
	input.event.file
	startswith(input.event.file.filename, "/lib/modules/")
	contains(input.event.file.filename, ".ko")
	input.event.file.op == 0  # open
	msg := sprintf("Kernel module accessed by %s (pid=%d): %s", [input.comm, input.pid, input.event.file.filename])
}

# Rule: /etc/hosts modification
# MITRE ATT&CK: T1565 - Data Manipulation
rules[{"rule_id": "hosts_file_modify", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1565", "matched": true}] {
	input.event.file
	input.event.file.filename == "/etc/hosts"
	input.event.file.op == 2  # write
	msg := sprintf("/etc/hosts modified by %s (pid=%d) - potential DNS hijacking", [input.comm, input.pid])
}

# Rule: /etc/resolv.conf modification
# MITRE ATT&CK: T1565 - Data Manipulation
rules[{"rule_id": "resolv_conf_modify", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1565", "matched": true}] {
	input.event.file
	input.event.file.filename == "/etc/resolv.conf"
	input.event.file.op == 2  # write
	msg := sprintf("/etc/resolv.conf modified by %s (pid=%d) - potential DNS hijacking", [input.comm, input.pid])
}

# Rule: Setuid binary execution
# MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism
rules[{"rule_id": "setuid_binary", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1548", "matched": true}] {
	input.event.file
	bits.and(input.event.file.mode, 2048) != 0  # SUID bit set (0o4000 = 2048)
	msg := sprintf("Setuid binary executed: %s by %s (pid=%d)", [input.event.file.filename, input.comm, input.pid])
}

# Helper: Check if process is a Kubernetes component
is_kubernetes_component(comm) {
	comm == "kubelet"
}

is_kubernetes_component(comm) {
	comm == "kube-proxy"
}

is_kubernetes_component(comm) {
	comm == "kubectl"
}

is_kubernetes_component(comm) {
	startswith(comm, "kube-")
}

# Helper: Check if process is a Docker component
is_docker_component(comm) {
	comm == "dockerd"
}

is_docker_component(comm) {
	comm == "docker"
}

is_docker_component(comm) {
	comm == "containerd"
}

# Helper: Check if process is a containerd component
is_containerd_component(comm) {
	comm == "containerd"
}

is_containerd_component(comm) {
	comm == "containerd-shim"
}

is_containerd_component(comm) {
	comm == "ctr"
}

# Helper: Check if process is a CRI-O component
is_crio_component(comm) {
	comm == "crio"
}

is_crio_component(comm) {
	startswith(comm, "crio-")
}

# Helper: Check if process is a shell
is_shell(comm) {
	comm == "bash"
}

is_shell(comm) {
	comm == "sh"
}

is_shell(comm) {
	comm == "zsh"
}

is_shell(comm) {
	comm == "dash"
}

is_shell(comm) {
	comm == "fish"
}

is_shell(comm) {
	comm == "python"
}

is_shell(comm) {
	comm == "python3"
}

is_shell(comm) {
	comm == "perl"
}

is_shell(comm) {
	comm == "ruby"
}

# contains() and startswith() are OPA built-ins; no wrappers needed.
