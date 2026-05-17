# OPA Unit Tests for Network Detection Rules
# Run with: opa test -v rules/rego/test/network_test.rego rules/rego/network.rego

package ebpf_guard.network.test

import data.ebpf_guard.network

# Test: Connection to mining pool port 3333
test_mining_port_3333 {
	input := {
		"pid": 1234,
		"comm": "xmrig",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 3333,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "cryptominer_connection"
	rules[0].severity == "critical"
	rules[0].action == "block"
}

# Test: Connection to mining pool port 3334
test_mining_port_3334 {
	input := {
		"pid": 1235,
		"comm": "minerd",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 3334,
				"daddr": [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "cryptominer_connection"
}

# Test: Connection to XMRig default port
test_xmrig_default_port {
	input := {
		"pid": 1236,
		"comm": "xmrig",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 45700,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "xmrig_default_port"
}

# Test: Private IP connection to mining port - should not match
test_private_ip_no_match {
	input := {
		"pid": 1237,
		"comm": "xmrig",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 3333,
				"daddr": [192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 0
}

# Test: Known miner process with network connection
test_miner_process_network {
	input := {
		"pid": 1238,
		"comm": "xmrig",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 8080,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "miner_process_network"
}

# Test: Miner named process
test_miner_named_process {
	input := {
		"pid": 1239,
		"comm": "my-miner-app",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 8080,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "miner_process_network"
}

# Test: Non-miner process - should not match miner rule
test_non_miner_no_match {
	input := {
		"pid": 1240,
		"comm": "nginx",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 8080,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 0
}

# Test: Privileged port connection by non-root
test_privileged_port_nonroot {
	input := {
		"pid": 1241,
		"comm": "curl",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 443,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "privileged_port_nonroot"
}

# Test: Privileged port by root - should not match
test_privileged_port_root_no_match {
	input := {
		"pid": 1242,
		"comm": "curl",
		"uid": 0,
		"event": {
			"network": {
				"dport": 443,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 0
}

# Test: Shell making external connection
test_shell_external_connection {
	input := {
		"pid": 1243,
		"comm": "bash",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 4444,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "rapid_connections"
}

# Test: Python making external connection (shell-like)
test_python_external_connection {
	input := {
		"pid": 1244,
		"comm": "python3",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 4444,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "rapid_connections"
}

# Test: Normal process external connection - should match rapid_connections
test_nginx_external_connection {
	input := {
		"pid": 1245,
		"comm": "nginx",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 8080,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 0
}

# Test: Tor OR port connection
test_tor_or_port {
	input := {
		"pid": 1246,
		"comm": "tor",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 9001,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "tor_connection"
}

# Test: Tor directory port connection
test_tor_dir_port {
	input := {
		"pid": 1247,
		"comm": "tor",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 9030,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) > 0
	rules[0].rule_id == "tor_connection_dir"
}

# Test: Private IP connection - no alerts expected
test_private_ip_connection {
	input := {
		"pid": 1248,
		"comm": "curl",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 8080,
				"daddr": [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 0
}

# Test: 172.16.x.x private range
test_private_ip_172 {
	input := {
		"pid": 1249,
		"comm": "curl",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 3333,
				"daddr": [172, 20, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 0
}

# Test: Loopback connection - no alerts
test_loopback_connection {
	input := {
		"pid": 1250,
		"comm": "xmrig",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 3333,
				"daddr": [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 0
}

# Test: Multiple rules can match
test_multiple_rules_match {
	input := {
		"pid": 1251,
		"comm": "xmrig",
		"uid": 1000,
		"event": {
			"network": {
				"dport": 3333,
				"daddr": [45, 9, 148, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				"proto": 6
			}
		}
	}
	
	rules := network.rules
	count(rules) == 2
	rules[0].rule_id == "cryptominer_connection"
	rules[1].rule_id == "miner_process_network"
}
