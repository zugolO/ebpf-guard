# OPA Unit Tests for Lineage Detection Rules
# Run with: opa test -v rules/rego/test/lineage_test.rego rules/rego/lineage.rego

package ebpf_guard.lineage.test

import data.ebpf_guard.lineage

# Test: Reverse shell from nginx to bash
test_reverse_shell_nginx_bash {
	input := {
		"pid": 1234,
		"comm": "bash",
		"event": {
			"parent_comm": "nginx",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "reverse_shell_webserver"
	rules[0].severity == "critical"
	rules[0].mitre_technique == "T1059"
}

# Test: Reverse shell from apache to sh
test_reverse_shell_apache_sh {
	input := {
		"pid": 1235,
		"comm": "sh",
		"event": {
			"parent_comm": "apache",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "reverse_shell_webserver"
}

# Test: No reverse shell - nginx to normal process
test_no_reverse_shell_nginx_normal {
	input := {
		"pid": 1236,
		"comm": "worker",
		"event": {
			"parent_comm": "nginx",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) == 0
}

# Test: No reverse shell - no parent comm
test_no_reverse_shell_no_parent {
	input := {
		"pid": 1237,
		"comm": "bash",
		"event": {
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) == 0
}

# Test: Shell from database - mysql to bash
test_shell_from_database_mysql {
	input := {
		"pid": 1238,
		"comm": "bash",
		"event": {
			"parent_comm": "mysql",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "shell_from_database"
	rules[0].severity == "critical"
}

# Test: Shell from database - postgres to python
test_shell_from_database_postgres {
	input := {
		"pid": 1239,
		"comm": "python3",
		"event": {
			"parent_comm": "postgres",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "shell_from_database"
}

# Test: Container escape via /proc/1/root
test_container_escape_proc_root {
	input := {
		"pid": 1240,
		"comm": "sh",
		"event": {
			"file": {
				"filename": "/proc/1/root/etc/passwd",
				"op": 0
			}
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "container_escape_proc"
	rules[0].action == "block"
}

# Test: Container escape via /proc/self/cwd/../
test_container_escape_cwd_traversal {
	input := {
		"pid": 1241,
		"comm": "bash",
		"event": {
			"file": {
				"filename": "/proc/self/cwd/../../../etc/shadow",
				"op": 0
			}
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "container_escape_proc"
}

# Test: Sudoers modification
test_sudoers_modification {
	input := {
		"pid": 1242,
		"comm": "vi",
		"event": {
			"file": {
				"filename": "/etc/sudoers",
				"op": 2
			}
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "sudoers_modification"
	rules[0].severity == "critical"
}

# Test: Sudoers read (not write) - should not match
test_sudoers_read_no_match {
	input := {
		"pid": 1243,
		"comm": "cat",
		"event": {
			"file": {
				"filename": "/etc/sudoers",
				"op": 1
			}
		}
	}
	
	rules := lineage.rules
	count(rules) == 0
}

# Test: SSH authorized_keys modification
test_authorized_keys_modify {
	input := {
		"pid": 1244,
		"comm": "echo",
		"event": {
			"file": {
				"filename": "/root/.ssh/authorized_keys",
				"op": 2
			}
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "authorized_keys_modify"
	rules[0].mitre_technique == "T1098"
}

# Test: SSH key access
test_ssh_key_access {
	input := {
		"pid": 1245,
		"comm": "cat",
		"event": {
			"file": {
				"filename": "/home/user/.ssh/id_rsa",
				"op": 1
			}
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "ssh_key_access"
	rules[0].severity == "warning"
}

# Test: SSH public key access - should not match
test_ssh_pubkey_no_match {
	input := {
		"pid": 1246,
		"comm": "cat",
		"event": {
			"file": {
				"filename": "/home/user/.ssh/id_rsa.pub",
				"op": 1
			}
		}
	}
	
	rules := lineage.rules
	count(rules) == 0
}

# Test: Init spawning shell
test_init_spawns_shell {
	input := {
		"pid": 1247,
		"comm": "bash",
		"event": {
			"parent_comm": "init",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "init_spawns_shell"
}

# Test: Cron spawning shell
test_cron_spawns_shell {
	input := {
		"pid": 1248,
		"comm": "sh",
		"event": {
			"parent_comm": "cron",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "cron_spawns_shell"
}

# Test: Package manager spawning shell - apt
test_package_manager_shell_apt {
	input := {
		"pid": 1249,
		"comm": "bash",
		"event": {
			"parent_comm": "apt",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "package_manager_shell"
}

# Test: Package manager spawning shell - pip
test_package_manager_shell_pip {
	input := {
		"pid": 1250,
		"comm": "python3",
		"event": {
			"parent_comm": "pip3",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) > 0
	rules[0].rule_id == "package_manager_shell"
}

# Test: Normal process - no match
test_normal_process_no_match {
	input := {
		"pid": 1251,
		"comm": "nginx",
		"event": {
			"parent_comm": "systemd",
			"type": 1
		}
	}
	
	rules := lineage.rules
	count(rules) == 0
}
