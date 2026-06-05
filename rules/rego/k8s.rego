# Kubernetes-specific attack detection rules (Rego)
# MITRE ATT&CK: T1528 (SA Token Theft), T1552 (Unsecured Credentials),
#               T1611 (Escape to Host), T1613 (Container/Resource Discovery)

package ebpf_guard.k8s

# Rule: Service Account token read by unexpected process
# MITRE ATT&CK: T1528 — Steal Application Access Token
rules[{"rule_id": "k8s_sa_token_theft", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1528", "matched": true}] {
	input.event.file
	startswith(input.event.file.filename, "/var/run/secrets/kubernetes.io/serviceaccount")
	not is_k8s_system_process(input.comm)
	msg := sprintf("SA token read by unexpected process %s (pid=%d) — T1528 credential theft", [input.comm, input.pid])
}

# Rule: Direct etcd connection — bypasses RBAC
# MITRE ATT&CK: T1552.001 — Credentials in Files (etcd stores all secrets)
rules[{"rule_id": "k8s_etcd_direct_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1552.001", "matched": true}] {
	input.event.network
	is_etcd_port(input.event.network.dport)
	not is_k8s_infra_process(input.comm)
	msg := sprintf("Direct etcd access on port %d by %s (pid=%d) — RBAC bypass T1552.001", [input.event.network.dport, input.comm, input.pid])
}

# Rule: Access to /etc/kubernetes/ from non-system process
# MITRE ATT&CK: T1611 — Escape to Host
rules[{"rule_id": "k8s_control_plane_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1611", "matched": true}] {
	input.event.file
	startswith(input.event.file.filename, "/etc/kubernetes/")
	not is_k8s_infra_process(input.comm)
	msg := sprintf("Control-plane path %s accessed by %s (pid=%d) — hostPath escape T1611", [input.event.file.filename, input.comm, input.pid])
}

# Rule: Cloud IMDS / metadata API access from pod
# MITRE ATT&CK: T1613 — Container and Resource Discovery
rules[{"rule_id": "k8s_imds_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1613", "matched": true}] {
	input.event.network
	is_imds_address(input.event.network.daddr)
	msg := sprintf("IMDS/metadata API access by %s (pid=%d) — cloud credential discovery T1613", [input.comm, input.pid])
}

# Rule: Container runtime socket access from pod context
# MITRE ATT&CK: T1552.007 — Container API
rules[{"rule_id": "k8s_runtime_socket_access", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1552.007", "matched": true}] {
	input.event.file
	is_runtime_socket(input.event.file.filename)
	msg := sprintf("Container runtime socket %s accessed by %s (pid=%d) — node takeover T1552.007", [input.event.file.filename, input.comm, input.pid])
}

# Helper: Known Kubernetes system processes that legitimately read SA tokens
is_k8s_system_process(comm) {
	comm == "kube-proxy"
}

is_k8s_system_process(comm) {
	comm == "kubelet"
}

is_k8s_system_process(comm) {
	comm == "coredns"
}

is_k8s_system_process(comm) {
	comm == "calico-node"
}

is_k8s_system_process(comm) {
	comm == "cilium-agent"
}

is_k8s_system_process(comm) {
	comm == "fluentd"
}

is_k8s_system_process(comm) {
	comm == "prometheus"
}

# Helper: Core Kubernetes infrastructure processes
is_k8s_infra_process(comm) {
	comm == "kube-apiserver"
}

is_k8s_infra_process(comm) {
	comm == "etcd"
}

is_k8s_infra_process(comm) {
	comm == "kubelet"
}

is_k8s_infra_process(comm) {
	comm == "kube-controller"
}

is_k8s_infra_process(comm) {
	comm == "kube-scheduler"
}

# Helper: etcd client and peer ports
is_etcd_port(port) {
	port == 2379
}

is_etcd_port(port) {
	port == 2380
}

# Helper: IMDS addresses (link-local)
is_imds_address(addr) {
	# 169.254.169.254 as byte array [169, 254, 169, 254]
	addr[0] == 169
	addr[1] == 254
	addr[2] == 169
	addr[3] == 254
}

is_imds_address(addr) {
	# 169.254.170.2 — ECS task metadata endpoint
	addr[0] == 169
	addr[1] == 254
	addr[2] == 170
	addr[3] == 2
}

# Helper: Container runtime sockets
is_runtime_socket(path) {
	path == "/run/containerd/containerd.sock"
}

is_runtime_socket(path) {
	path == "/var/run/containerd/containerd.sock"
}

is_runtime_socket(path) {
	path == "/run/crio/crio.sock"
}

is_runtime_socket(path) {
	path == "/var/run/crio/crio.sock"
}

is_runtime_socket(path) {
	path == "/var/run/docker.sock"
}

is_runtime_socket(path) {
	path == "/run/docker.sock"
}
