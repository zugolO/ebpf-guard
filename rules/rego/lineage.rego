# Lineage-based detection rules
# Detects suspicious process relationships and container escapes

package ebpf_guard.lineage

# Rule: Reverse shell from web server
# MITRE ATT&CK: T1059 - Command and Scripting Interpreter
rules[{"rule_id": "reverse_shell_webserver", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1059", "matched": true}] {
	input.event.parent_comm
	is_webserver(input.event.parent_comm)
	is_shell(input.comm)
	not input.event.file  # Not a file operation
	msg := sprintf("Potential reverse shell: %s spawned from %s (pid=%d)", [input.comm, input.event.parent_comm, input.pid])
}

# Rule: Shell spawned from database
# MITRE ATT&CK: T1190 - Exploit Public-Facing Application
rules[{"rule_id": "shell_from_database", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1190", "matched": true}] {
	input.event.parent_comm
	is_database(input.event.parent_comm)
	is_shell(input.comm)
	msg := sprintf("Shell spawned from database: %s from %s (pid=%d)", [input.comm, input.event.parent_comm, input.pid])
}

# Rule: Container escape via /proc
# MITRE ATT&CK: T1611 - Escape to Host
rules[{"rule_id": "container_escape_proc", "severity": "critical", "message": msg, "action": "block", "mitre_technique": "T1611", "matched": true}] {
	input.event.file
	is_container_escape_path(input.event.file.filename)
	msg := sprintf("Container escape attempt via %s (pid=%d, comm=%s)", [input.event.file.filename, input.pid, input.comm])
}

# Rule: Privilege escalation via sudoers modification
# MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism
rules[{"rule_id": "sudoers_modification", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1548", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, "/etc/sudoers")
	input.event.file.op == 2  # write operation
	msg := sprintf("Sudoers file modification attempt (pid=%d, comm=%s)", [input.pid, input.comm])
}

# Rule: SSH key access
# MITRE ATT&CK: T1552 - Unsecured Credentials
rules[{"rule_id": "ssh_key_access", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1552", "matched": true}] {
	input.event.file
	contains(input.event.file.filename, ".ssh/")
	contains(input.event.file.filename, "id_")
	msg := sprintf("SSH private key access: %s (pid=%d, comm=%s)", [input.event.file.filename, input.pid, input.comm])
}

# Rule: Suspicious parent-child: init spawning shell
# MITRE ATT&CK: T1037 - Boot or Logon Initialization Scripts
rules[{"rule_id": "init_spawns_shell", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1037", "matched": true}] {
	input.event.parent_comm == "init"
	is_shell(input.comm)
	msg := sprintf("Shell spawned from init: %s (pid=%d)", [input.comm, input.pid])
}

# Rule: Suspicious parent-child: cron spawning shell
# MITRE ATT&CK: T1053 - Scheduled Task/Job
rules[{"rule_id": "cron_spawns_shell", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1053", "matched": true}] {
	input.event.parent_comm == "cron"
	is_shell(input.comm)
	msg := sprintf("Shell spawned from cron: %s (pid=%d)", [input.comm, input.pid])
}

# Rule: Suspicious parent-child: apt/yum spawning shell
# MITRE ATT&CK: T1071 - Application Layer Protocol (supply chain)
rules[{"rule_id": "package_manager_shell", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1071", "matched": true}] {
	is_package_manager(input.event.parent_comm)
	is_shell(input.comm)
	msg := sprintf("Shell spawned from package manager: %s from %s (pid=%d)", [input.comm, input.event.parent_comm, input.pid])
}

# Helper: Check if process is a package manager
is_package_manager(comm) {
	comm == "apt"
}

is_package_manager(comm) {
	comm == "apt-get"
}

is_package_manager(comm) {
	comm == "yum"
}

is_package_manager(comm) {
	comm == "dnf"
}

is_package_manager(comm) {
	comm == "pip"
}

is_package_manager(comm) {
	comm == "pip3"
}

is_package_manager(comm) {
	comm == "npm"
}

# Helper: Check if process is a web server (redefined for this package)
is_webserver(comm) {
	comm == "nginx"
}

is_webserver(comm) {
	comm == "apache"
}

is_webserver(comm) {
	comm == "apache2"
}

is_webserver(comm) {
	comm == "httpd"
}

is_webserver(comm) {
	comm == "lighttpd"
}

is_webserver(comm) {
	comm == "caddy"
}

# Helper: Check if process is a database (redefined for this package)
is_database(comm) {
	comm == "mysql"
}

is_database(comm) {
	comm == "postgres"
}

is_database(comm) {
	comm == "mongodb"
}

is_database(comm) {
	comm == "redis-server"
}

# Helper: Check if process is a shell (redefined for this package)
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

# Helper: Check if path is a container escape target (redefined for this package)
is_container_escape_path(path) {
	startswith(path, "/proc/1/root")
}

is_container_escape_path(path) {
	startswith(path, "/proc/self/cwd")
	contains(path, "../")
}

is_container_escape_path(path) {
	startswith(path, "/proc/self/root")
}
