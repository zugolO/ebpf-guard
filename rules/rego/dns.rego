# DNS-based detection rules
# Detects DNS tunneling, DGA domains, and suspicious DNS queries

package ebpf_guard.dns

# Rule: DNS query to known DGA pattern (high entropy domain)
# MITRE ATT&CK: T1568.002 - Dynamic Resolution: Domain Generation Algorithms
rules[{"rule_id": "dga_domain", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1568.002", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	is_dga_domain(input.event.dns.qname)
	msg := sprintf("Possible DGA domain: %s queried by %s (pid=%d)", [input.event.dns.qname, input.comm, input.pid])
}

# Rule: DNS query to suspicious TLD
# MITRE ATT&CK: T1071.004 - Application Layer Protocol: DNS
rules[{"rule_id": "suspicious_tld", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1071.004", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	is_suspicious_tld(input.event.dns.qname)
	msg := sprintf("Suspicious TLD in DNS query: %s by %s (pid=%d)", [input.event.dns.qname, input.comm, input.pid])
}

# Rule: DNS TXT record query (often used for tunneling)
# MITRE ATT&CK: T1071.004 - Application Layer Protocol: DNS
rules[{"rule_id": "dns_txt_query", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1071.004", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	input.event.dns.qtype == 16  # TXT record
	not is_dns_tool(input.comm)
	msg := sprintf("DNS TXT query (potential tunneling): %s by %s (pid=%d)", [input.event.dns.qname, input.comm, input.pid])
}

# Rule: DNS query for known mining pool domain
# MITRE ATT&CK: T1496 - Resource Hijacking
rules[{"rule_id": "mining_pool_dns", "severity": "critical", "message": msg, "action": "block", "mitre_technique": "T1496", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	is_mining_domain(input.event.dns.qname)
	msg := sprintf("DNS query to mining pool: %s by %s (pid=%d)", [input.event.dns.qname, input.comm, input.pid])
}

# Rule: DNS query to Tor exit node domain
# MITRE ATT&CK: T1090 - Proxy
rules[{"rule_id": "tor_dns_query", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1090", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	contains(lower(input.event.dns.qname), "tor")
	contains(lower(input.event.dns.qname), "exit")
	msg := sprintf("DNS query to Tor exit: %s by %s (pid=%d)", [input.event.dns.qname, input.comm, input.pid])
}

# Rule: Long DNS query (potential tunneling)
# MITRE ATT&CK: T1071.004 - Application Layer Protocol: DNS
rules[{"rule_id": "long_dns_query", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1071.004", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	count(input.event.dns.qname) > 50
	not is_dns_tool(input.comm)
	msg := sprintf("Long DNS query (potential tunneling): %s (len=%d) by %s", [input.event.dns.qname, count(input.event.dns.qname), input.comm])
}

# Rule: DNS query to dynamic DNS service
# MITRE ATT&CK: T1568.001 - Dynamic Resolution: Fast Flux DNS
rules[{"rule_id": "dynamic_dns_query", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1568.001", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	is_dynamic_dns_domain(input.event.dns.qname)
	msg := sprintf("Dynamic DNS query: %s by %s (pid=%d)", [input.event.dns.qname, input.comm, input.pid])
}

# Rule: NXDOMAIN response rate (potential DGA)
# MITRE ATT&CK: T1568.002 - Dynamic Resolution: Domain Generation Algorithms
rules[{"rule_id": "nxdomain_response", "severity": "warning", "message": msg, "action": "alert", "mitre_technique": "T1568.002", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 1  # response
	input.event.dns.rcode == 3  # NXDOMAIN
	is_shell(input.comm)
	msg := sprintf("NXDOMAIN response for %s queried by %s (potential DGA)", [input.event.dns.qname, input.comm])
}

# Rule: DNS query from miner process
# MITRE ATT&CK: T1496 - Resource Hijacking
rules[{"rule_id": "miner_dns_query", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1496", "matched": true}] {
	input.event.dns
	input.event.dns.direction == 0  # query
	is_miner(input.comm)
	msg := sprintf("DNS query from miner %s: %s", [input.comm, input.event.dns.qname])
}

# Helper: Check if domain looks like DGA (high entropy)
is_dga_domain(domain) {
	# Remove TLD
	parts := split(domain, ".")
	count(parts) > 1
	name := parts[0]
	
	# Check length
	count(name) > 12
	
	# Check entropy (simplified - high entropy indicator)
	not contains_dictionary_word(name)
	contains_digit(name)
}

# Helper: Check if domain contains dictionary word
contains_dictionary_word(name) {
	contains(lower(name), "www")
}

contains_dictionary_word(name) {
	contains(lower(name), "mail")
}

contains_dictionary_word(name) {
	contains(lower(name), "ftp")
}

contains_dictionary_word(name) {
	contains(lower(name), "smtp")
}

contains_dictionary_word(name) {
	contains(lower(name), "pop")
}

contains_dictionary_word(name) {
	contains(lower(name), "imap")
}

contains_dictionary_word(name) {
	contains(lower(name), "ns")
}

contains_dictionary_word(name) {
	contains(lower(name), "dns")
}

contains_dictionary_word(name) {
	contains(lower(name), "api")
}

contains_dictionary_word(name) {
	contains(lower(name), "cdn")
}

contains_dictionary_word(name) {
	contains(lower(name), "app")
}

contains_dictionary_word(name) {
	contains(lower(name), "blog")
}

contains_dictionary_word(name) {
	contains(lower(name), "shop")
}

contains_dictionary_word(name) {
	contains(lower(name), "news")
}

contains_dictionary_word(name) {
	contains(lower(name), "mail")
}

# Helper: Check if string contains digit
contains_digit(s) {
	contains(s, "0")
}

contains_digit(s) {
	contains(s, "1")
}

contains_digit(s) {
	contains(s, "2")
}

contains_digit(s) {
	contains(s, "3")
}

contains_digit(s) {
	contains(s, "4")
}

contains_digit(s) {
	contains(s, "5")
}

contains_digit(s) {
	contains(s, "6")
}

contains_digit(s) {
	contains(s, "7")
}

contains_digit(s) {
	contains(s, "8")
}

contains_digit(s) {
	contains(s, "9")
}

# Helper: Check if TLD is suspicious
is_suspicious_tld(domain) {
	endswith(lower(domain), ".tk")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".ml")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".ga")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".cf")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".gq")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".top")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".xyz")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".click")
}

is_suspicious_tld(domain) {
	endswith(lower(domain), ".link")
}

# Helper: Check if domain is a known mining pool
is_mining_domain(domain) {
	contains(lower(domain), "xmrig")
}

is_mining_domain(domain) {
	contains(lower(domain), "minexmr")
}

is_mining_domain(domain) {
	contains(lower(domain), "supportxmr")
}

is_mining_domain(domain) {
	contains(lower(domain), "nanopool")
}

is_mining_domain(domain) {
	contains(lower(domain), "pool")
	contains(lower(domain), "mine")
}

is_mining_domain(domain) {
	contains(lower(domain), "stratum")
}

is_mining_domain(domain) {
	contains(lower(domain), "hashvault")
}

is_mining_domain(domain) {
	contains(lower(domain), "moneroocean")
}

# Helper: Check if domain is dynamic DNS
is_dynamic_dns_domain(domain) {
	contains(lower(domain), "ddns")
}

is_dynamic_dns_domain(domain) {
	contains(lower(domain), "dyndns")
}

is_dynamic_dns_domain(domain) {
	contains(lower(domain), "no-ip")
}

is_dynamic_dns_domain(domain) {
	contains(lower(domain), "duckdns")
}

is_dynamic_dns_domain(domain) {
	endswith(lower(domain), ".hopto.org")
}

is_dynamic_dns_domain(domain) {
	endswith(lower(domain), ".zapto.org")
}

is_dynamic_dns_domain(domain) {
	endswith(lower(domain), ".sytes.net")
}

is_dynamic_dns_domain(domain) {
	endswith(lower(domain), ".ddns.net")
}

# Helper: Check if process is a known miner
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
	contains(lower(comm), "miner")
}

is_miner(comm) {
	contains(lower(comm), "xmr")
}

# Helper: Check if process is a DNS tool (legitimate)
is_dns_tool(comm) {
	comm == "dig"
}

is_dns_tool(comm) {
	comm == "nslookup"
}

is_dns_tool(comm) {
	comm == "host"
}

is_dns_tool(comm) {
	comm == "resolvectl"
}

is_dns_tool(comm) {
	comm == "systemd-resolve"
}

is_dns_tool(comm) {
	comm == "unbound"
}

is_dns_tool(comm) {
	comm == "dnsmasq"
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

# lower(), contains(), endswith(), count() are OPA built-ins; no wrappers needed.
