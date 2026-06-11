// Package attacker implements safe attack simulation scenarios that reproduce
// behaviors detected by the built-in rule sets. Each scenario generates a
// synthetic event that should trigger one or more known rules, allowing
// end-to-end detection smoke tests without real malicious payloads.
package attacker

import (
	"net"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Scenario describes a single attack simulation.
type Scenario struct {
	// ID is the stable identifier used with --scenario.
	ID string
	// Name is the human-readable scenario title.
	Name string
	// Description explains what the scenario simulates.
	Description string
	// RuleIDs lists the ebpf-guard rule IDs expected to fire.
	RuleIDs []string
	// MITRETech is the primary MITRE ATT&CK technique (e.g. "T1548.001").
	MITRETech string
	// Event generates the synthetic event for offline (no-agent) testing.
	Event func() types.Event
}

// BuiltinScenarios returns all built-in attack scenarios.
// Each scenario is mapped 1:1 to a rule set shipped with ebpf-guard.
func BuiltinScenarios() []Scenario {
	return []Scenario{
		containerEscapePtrace(),
		cryptominerPoolConnect(),
		dgaDNSQuery(),
		ldpreloadDrop(),
		sensitiveFileRead(),
		privEscCapSysAdmin(),
		kmodLoad(),
	}
}

// ScenarioByID returns the scenario with the given ID, or (_, false).
func ScenarioByID(id string) (Scenario, bool) {
	for _, s := range BuiltinScenarios() {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

// ── helpers ───────────────────────────────────────────────────────────────────

func ts() uint64 { return uint64(time.Now().UnixNano()) }

func comm(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func ipv4(addr string) [16]byte {
	var b [16]byte
	if p := net.ParseIP(addr).To4(); p != nil {
		copy(b[:4], p)
	}
	return b
}

func filename(path string) [256]byte {
	var b [256]byte
	copy(b[:], path)
	return b
}

// ── scenarios ─────────────────────────────────────────────────────────────────

func containerEscapePtrace() Scenario {
	return Scenario{
		ID:          "container-escape-ptrace",
		Name:        "Container Escape via ptrace",
		Description: "SYS_ptrace(PTRACE_ATTACH) targeting PID 1 — escapes the container PID namespace.",
		RuleIDs:     []string{"container_escape_ptrace"},
		MITRETech:   "T1611",
		Event: func() types.Event {
			return types.Event{
				Type:      types.EventSyscall,
				Timestamp: ts(),
				PID:       99990,
				TGID:      99990,
				Comm:      comm("escape-probe"),
				Syscall: &types.SyscallEvent{
					Nr:   101,                             // SYS_ptrace
					Args: [6]uint64{0 /*PTRACE_ATTACH*/, 1 /*target PID 1*/, 0, 0, 0, 0},
				},
			}
		},
	}
}

func cryptominerPoolConnect() Scenario {
	return Scenario{
		ID:          "cryptominer-pool-connect",
		Name:        "Cryptominer Pool Connection",
		Description: "TCP connect to port 3333 (Stratum mining protocol), sinkholed to 127.0.0.1.",
		RuleIDs:     []string{"cryptominer_pool_connect"},
		MITRETech:   "T1496",
		Event: func() types.Event {
			return types.Event{
				Type:      types.EventTCPConnect,
				Timestamp: ts(),
				PID:       99991,
				Comm:      comm("xmrig-sim"),
				Network: &types.NetworkEvent{
					Saddr:  ipv4("127.0.0.1"),
					Daddr:  ipv4("127.0.0.1"), // sinkhole — no real outbound traffic
					Sport:  54321,
					Dport:  3333, // Stratum mining port
					Family: types.AFInet,
				},
			}
		},
	}
}

func dgaDNSQuery() Scenario {
	return Scenario{
		ID:          "dga-dns-query",
		Name:        "DGA-style DNS Query",
		Description: "DNS A-record query with a high-entropy domain label matching the DGA pattern.",
		RuleIDs:     []string{"dns_dga_query"},
		MITRETech:   "T1568.002",
		Event: func() types.Event {
			return types.Event{
				Type:      types.EventDNS,
				Timestamp: ts(),
				PID:       99992,
				Comm:      comm("malware-sim"),
				DNS: &types.DNSEvent{
					// High-entropy label (>3.5 bits/char Shannon entropy).
					QName:     "xvzqwkjpmlhbfrtns.c2.example.com",
					QType:     1, // A record
					Direction: types.DNSDirectionQuery,
				},
			}
		},
	}
}

func ldpreloadDrop() Scenario {
	return Scenario{
		ID:          "ldpreload-drop",
		Name:        "LD_PRELOAD Injection",
		Description: "Open /etc/ld.so.preload for writing — drops a shared-library injection hook.",
		RuleIDs:     []string{"ldpreload_injection"},
		MITRETech:   "T1574.006",
		Event: func() types.Event {
			return types.Event{
				Type:      types.EventFileAccess,
				Timestamp: ts(),
				PID:       99993,
				Comm:      comm("attacker"),
				File: &types.FileEvent{
					Filename: filename("/etc/ld.so.preload"),
					Flags:    0x1, // O_WRONLY
					Op:       2,   // write
				},
			}
		},
	}
}

func sensitiveFileRead() Scenario {
	return Scenario{
		ID:          "sensitive-file-read",
		Name:        "Sensitive File Read (/etc/shadow)",
		Description: "Non-root process opens /etc/shadow for reading.",
		RuleIDs:     []string{"sensitive_file_read"},
		MITRETech:   "T1003.008",
		Event: func() types.Event {
			return types.Event{
				Type:      types.EventFileAccess,
				Timestamp: ts(),
				PID:       99994,
				UID:       1000, // non-root
				Comm:      comm("cat-sim"),
				File: &types.FileEvent{
					Filename: filename("/etc/shadow"),
					Flags:    0x0, // O_RDONLY
					Op:       0,   // open
				},
			}
		},
	}
}

func privEscCapSysAdmin() Scenario {
	return Scenario{
		ID:          "privesc-cap-sys-admin",
		Name:        "Privilege Escalation (CAP_SYS_ADMIN)",
		Description: "Process gains CAP_SYS_ADMIN (bit 21) capability — most powerful Linux privilege.",
		RuleIDs:     []string{"privesc_sys_admin_gained"},
		MITRETech:   "T1548.001",
		Event: func() types.Event {
			const capSysAdmin = uint64(1) << 21
			return types.Event{
				Type:      types.EventPrivesc,
				Timestamp: ts(),
				PID:       99995,
				Comm:      comm("exploit-sim"),
				Privesc: &types.PrivescEvent{
					OldCaps: 0,
					NewCaps: capSysAdmin,
				},
			}
		},
	}
}

func kmodLoad() Scenario {
	return Scenario{
		ID:          "kmod-load",
		Name:        "Kernel Module Load",
		Description: "Loads a kernel module from /tmp (common rootkit delivery vector).",
		RuleIDs:     []string{"kmod_from_tmpfs"},
		MITRETech:   "T1547.006",
		Event: func() types.Event {
			return types.Event{
				Type:      types.EventKmodLoad,
				Timestamp: ts(),
				PID:       99996,
				Comm:      comm("insmod-sim"),
				Kmod: &types.KmodEvent{
					ModName:   "evil.ko",
					FromTmpfs: true,
				},
			}
		},
	}
}
