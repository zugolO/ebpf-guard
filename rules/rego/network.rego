# Network-based detection rules
# Detects cryptominer connections, C2 communications, and suspicious network activity

package ebpf_guard.network

# Rule: Connection to known mining pool port
# MITRE ATT&CK: T1496 - Resource Hijacking
rules[{"rule_id": "cryptominer_connection", "severity": "critical", "message": msg, "action": "block", "mitre_technique": "T1496", "matched": true}] {
	input.event.network
	is_mining_port(input.event.network.dport)
	not is_private_ip(input.event.network.daddr)
	msg := sprintf("Connection to mining pool port %d from %s (pid=%d)", [input.event.network.dport, input.comm, input.pid])
}

# Rule: XMRig default port connection
# MITRE ATT&CK: T1496 - Resource Hijacking
rules[{"rule_id": "xmrig_default_port", "severity": "critical", "message": msg, "action": "block", "mitre_technique": "T1496", "matched": true}] {
	input.event.network
	input.event.network.dport == 45700
	msg := sprintf("XMRig proxy connection detected from %s (pid=%d)", [input.comm, input.pid])
}

# Rule: Known miner process with network connection
# MITRE ATT&CK: T1496 - Resource Hijacking
rules[{"rule_id": "miner_process_network", "severity": "critical", "message": msg, "action": "block", "mitre_technique": "T1496", "matched": true}] {
	input.event.network
	is_miner(input.comm)
	msg := sprintf("Known miner %s making network connection (pid=%d, port=%d)", [input.comm, input.pid, input.event.network.dport])
}

# Rule: Outbound connection on privileged port (non-root)
# MITRE ATT&CK: T1048 - Exfiltration Over Alternative Protocol
rules[{"rule_id": "privileged_port_nonroot", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1048", "matched": true}] {
	input.event.network
	is_privileged_port(input.event.network.dport)
	input.uid != 0
	not is_private_ip(input.event.network.daddr)
	msg := sprintf("Non-root process %s (uid=%d) connecting to privileged port %d", [input.comm, input.uid, input.event.network.dport])
}

# Rule: Connection to non-standard SSH port
# MITRE ATT&CK: T1021 - Remote Services
rules[{"rule_id": "ssh_nonstandard_port", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1021", "matched": true}] {
	input.event.network
	input.event.network.dport != 22
	input.event.network.dport > 1024
	is_ssh_like_traffic(input)
	msg := sprintf("Possible SSH on non-standard port %d from %s (pid=%d)", [input.event.network.dport, input.comm, input.pid])
}

# Rule: Multiple connections to same destination (potential C2)
# Note: This requires state tracking, simplified version here
# MITRE ATT&CK: T1071 - Application Layer Protocol
rules[{"rule_id": "rapid_connections", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1071", "matched": true}] {
	input.event.network
	input.event.network.proto == 6  # TCP
	not is_private_ip(input.event.network.daddr)
	is_shell(input.comm)
	msg := sprintf("Shell %s making external connection to %d.%d.%d.%d:%d", [input.comm, input.event.network.daddr[0], input.event.network.daddr[1], input.event.network.daddr[2], input.event.network.daddr[3], input.event.network.dport])
}

# Rule: DNS over HTTPS (DoH) - potential tunneling
# MITRE ATT&CK: T1071.004 - Application Layer Protocol: DNS
rules[{"rule_id": "dns_over_https", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1071.004", "matched": true}] {
	input.event.network
	input.event.network.dport == 443
	is_dns_process(input.comm)
	msg := sprintf("DNS process %s using HTTPS port (potential DoH tunneling)", [input.comm])
}

# Rule: Connection to Tor entry node port
# MITRE ATT&CK: T1090 - Proxy
rules[{"rule_id": "tor_connection", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1090", "matched": true}] {
	input.event.network
	input.event.network.dport == 9001  # Tor OR port
	msg := sprintf("Connection to Tor port from %s (pid=%d)", [input.comm, input.pid])
}

rules[{"rule_id": "tor_connection_dir", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1090", "matched": true}] {
	input.event.network
	input.event.network.dport == 9030  # Tor Dir port
	msg := sprintf("Connection to Tor directory port from %s (pid=%d)", [input.comm, input.pid])
}

# Helper: Check if port is a mining pool port
is_mining_port(port) {
	port == 3333  # Stratum (TCP)
}

is_mining_port(port) {
	port == 3334  # Stratum (TCP/SSL)
}

is_mining_port(port) {
	port == 45700 # XMRig proxy
}

is_mining_port(port) {
	port == 45560 # xmrig
}

is_mining_port(port) {
	port == 14444 # NiceHash
}

is_mining_port(port) {
	port == 45700 # MiningPoolHub
}

# Helper: Check if port is privileged
is_privileged_port(port) {
	port < 1024
}

# Helper: Check if IP is private
is_private_ip(ip_bytes) {
	ip_bytes[0] == 10
}

is_private_ip(ip_bytes) {
	ip_bytes[0] == 172
	ip_bytes[1] >= 16
	ip_bytes[1] <= 31
}

is_private_ip(ip_bytes) {
	ip_bytes[0] == 192
	ip_bytes[1] == 168
}

is_private_ip(ip_bytes) {
	ip_bytes[0] == 127
}

# Helper: Check if process is a miner
is_miner(comm) {
	comm == "xmrig"
}

is_miner(comm) {
	comm == "minerd"
}

is_miner(comm) {
	comm == "cgminer"
}

is_miner(comm) {
	comm == "bfgminer"
}

is_miner(comm) {
	comm == "stratum"
}

is_miner(comm) {
	contains(lower(comm), "miner")
}

is_miner(comm) {
	contains(lower(comm), "xmr")
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

# Helper: Check if process is DNS-related
is_dns_process(comm) {
	comm == "dig"
}

is_dns_process(comm) {
	comm == "nslookup"
}

is_dns_process(comm) {
	comm == "host"
}

is_dns_process(comm) {
	comm == "resolvectl"
}

# Helper: Check for SSH-like traffic patterns
is_ssh_like_traffic(conn) {
	# Simplified check - in production would analyze packet patterns
	conn.event.network.dport >= 2222
	conn.event.network.dport <= 2229
}

# lower() and contains() are OPA built-ins; no wrappers needed.
