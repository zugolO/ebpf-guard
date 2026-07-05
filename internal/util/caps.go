package util

import "fmt"

// capabilityNames maps Linux capability bit index to human-readable name.
// Covers capabilities 0–40 (CAP_LAST_CAP on Linux 5.x is typically 40). See
// <linux/capability.h>.
//
// This is the single shared table backing collector.CapsToNames (used to
// label privilege-escalation events) and sandbox's tamper-capability check
// (internal/sandbox/privilege.go): before this both kept independent copies
// of the same bit->name mapping, which could silently diverge (issue #271).
var capabilityNames = [...]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
	38: "CAP_PERFMON",
	39: "CAP_BPF",
	40: "CAP_CHECKPOINT_RESTORE",
}

// CapsToNames converts a capability bitmask to a slice of human-readable
// names, in ascending bit order. Bits beyond the known table render as
// "CAP_<n>" rather than being dropped, so an unrecognised/future capability
// bit is still surfaced.
func CapsToNames(caps uint64) []string {
	var names []string
	for i := 0; i < 64; i++ {
		if caps&(1<<uint(i)) != 0 {
			if i < len(capabilityNames) && capabilityNames[i] != "" {
				names = append(names, capabilityNames[i])
			} else {
				names = append(names, fmt.Sprintf("CAP_%d", i))
			}
		}
	}
	return names
}
