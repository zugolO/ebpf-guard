package ebpf_guard.admission

# deny rules: return set of violation messages — pod is blocked in "enforce" mode.
# warn rules: return advisory messages — pod is admitted but warnings are surfaced.

# ---------------------------------------------------------------------------
# Host-level privilege escalation
# ---------------------------------------------------------------------------

deny[msg] {
	input.request.object.spec.hostNetwork == true
	not _is_system_namespace(input.request.namespace)
	msg = "hostNetwork is not allowed outside system namespaces"
}

deny[msg] {
	input.request.object.spec.hostPID == true
	not _is_system_namespace(input.request.namespace)
	msg = "hostPID is not allowed outside system namespaces"
}

deny[msg] {
	input.request.object.spec.hostIPC == true
	not _is_system_namespace(input.request.namespace)
	msg = "hostIPC is not allowed outside system namespaces"
}

# ---------------------------------------------------------------------------
# Privileged containers
# ---------------------------------------------------------------------------

warn[msg] {
	container := _all_containers[_]
	container.securityContext.privileged == true
	msg = sprintf("privileged container detected: %s", [container.name])
}

# ---------------------------------------------------------------------------
# Dangerous capabilities
# ---------------------------------------------------------------------------

_dangerous_caps = {
	"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
	"SYS_RAWIO", "DAC_READ_SEARCH", "SETUID", "SETGID",
}

warn[msg] {
	container := _all_containers[_]
	cap := container.securityContext.capabilities.add[_]
	_dangerous_caps[cap]
	msg = sprintf("container %s requests dangerous capability: %s", [container.name, cap])
}

# ---------------------------------------------------------------------------
# Root user
# ---------------------------------------------------------------------------

warn[msg] {
	container := _all_containers[_]
	container.securityContext.runAsUser == 0
	msg = sprintf("container %s runs as root (uid 0)", [container.name])
}

deny[msg] {
	container := _all_containers[_]
	container.securityContext.allowPrivilegeEscalation == true
	msg = sprintf("container %s allows privilege escalation", [container.name])
}

# ---------------------------------------------------------------------------
# Host path mounts
# ---------------------------------------------------------------------------

warn[msg] {
	vol := input.request.object.spec.volumes[_]
	vol.hostPath
	not _safe_host_path(vol.hostPath.path)
	msg = sprintf("hostPath volume %s mounts sensitive host path: %s", [vol.name, vol.hostPath.path])
}

_safe_host_path(path) {
	safe_paths := {"/sys/kernel/btf", "/sys/fs/bpf", "/proc"}
	p := safe_paths[_]
	startswith(path, p)
}

# ---------------------------------------------------------------------------
# Image policy
# ---------------------------------------------------------------------------

warn[msg] {
	container := _all_containers[_]
	endswith(container.image, ":latest")
	msg = sprintf("container %s uses :latest tag - pin to a digest for reproducibility", [container.name])
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_system_namespaces = {"kube-system", "kube-public", "kube-node-lease"}

_is_system_namespace(ns) {
	_system_namespaces[ns]
}

_all_containers[c] {
	c := input.request.object.spec.containers[_]
}

_all_containers[c] {
	c := input.request.object.spec.initContainers[_]
}

_all_containers[c] {
	c := input.request.object.spec.ephemeralContainers[_]
}
