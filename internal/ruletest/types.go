// Package ruletest implements a declarative YAML unit-testing framework for
// ebpf-guard detection rules. Tests run without a real kernel, BPF programs, or
// K8s cluster — only the rule engine is exercised.
package ruletest

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Expectation is the expected test outcome.
type Expectation string

const (
	ExpectAlert   Expectation = "alert"
	ExpectNoAlert Expectation = "no_alert"
	ExpectDrop    Expectation = "drop"
)

// Suite is a parsed *_test.yaml file containing one or more test cases.
type Suite struct {
	// Suite is the human-readable name for this test suite.
	Suite string `yaml:"suite"`
	// RulesPath is an optional path (relative to the YAML file) to the rule
	// file or directory to load before running the tests.
	// When empty the caller must supply rules via the Runner.RulesDir option.
	RulesPath string `yaml:"rules_path,omitempty"`
	// Tests is the list of test cases in this suite.
	Tests []TestCase `yaml:"tests"`
}

// TestCase is a single unit test that exercises one synthetic event.
type TestCase struct {
	// Name is a human-readable description of the test case.
	Name string `yaml:"name"`
	// RuleID documents which rule this test is primarily exercising.
	// Used as annotation and, when Expect=alert, the named rule must be
	// among the rules that fired (unless overridden by ExpectRuleID).
	RuleID string `yaml:"rule_id,omitempty"`
	// Event is the synthetic event to inject into the rule engine.
	Event EventSpec `yaml:"event"`
	// Expect is the required outcome: "alert", "no_alert", or "drop".
	Expect Expectation `yaml:"expect"`
	// ExpectSeverity, when non-empty, asserts that at least one fired alert
	// carries this severity level ("warning" or "critical").
	ExpectSeverity string `yaml:"expect_severity,omitempty"`
	// ExpectRuleID, when non-empty, asserts that this specific rule ID must
	// have fired (overrides RuleID for assertion purposes).
	ExpectRuleID string `yaml:"expect_rule_id,omitempty"`
}

// effectiveExpectRuleID returns the rule ID that the test asserts must fire.
// ExpectRuleID takes priority over RuleID. Returns "" if no assertion is set.
func (tc TestCase) effectiveExpectRuleID() string {
	if tc.ExpectRuleID != "" {
		return tc.ExpectRuleID
	}
	return tc.RuleID
}

// ─────────────────────────────────────────────────────────────────────────────
// Event specification types
// ─────────────────────────────────────────────────────────────────────────────

// EventSpec describes a synthetic event in YAML.
type EventSpec struct {
	Type    string       `yaml:"type"`
	PID     uint32       `yaml:"pid,omitempty"`
	TGID    uint32       `yaml:"tgid,omitempty"`
	UID     uint32       `yaml:"uid,omitempty"`
	Comm    string       `yaml:"comm,omitempty"`
	Syscall *SyscallSpec `yaml:"syscall,omitempty"`
	Network *NetworkSpec `yaml:"network,omitempty"`
	File    *FileSpec    `yaml:"file,omitempty"`
	DNS     *DNSSpec     `yaml:"dns,omitempty"`
	Privesc *PrivescSpec `yaml:"privesc,omitempty"`
	TLS     *TLSSpec     `yaml:"tls,omitempty"`
}

// TLSSpec describes a TLS plaintext inspection event payload.
type TLSSpec struct {
	// Data is the plaintext payload (first 256 bytes).
	Data string `yaml:"data,omitempty"`
	// DataLen overrides the payload length reported by the event.
	// When omitted, len(Data) is used.
	DataLen uint32 `yaml:"data_len,omitempty"`
	// Direction is "write" (outbound, default) or "read" (inbound).
	Direction string `yaml:"direction,omitempty"`
}

// SyscallSpec describes a syscall event payload.
type SyscallSpec struct {
	NR   int64    `yaml:"nr"`
	Ret  int64    `yaml:"ret,omitempty"`
	Args []uint64 `yaml:"args,omitempty"`
}

// NetworkSpec describes a TCP-connect event payload.
type NetworkSpec struct {
	SrcIP  string `yaml:"src_ip,omitempty"`
	DstIP  string `yaml:"dst_ip,omitempty"`
	Sport  uint16 `yaml:"sport,omitempty"`
	Dport  uint16 `yaml:"dport,omitempty"`
	Family string `yaml:"family,omitempty"` // "ipv4" (default) or "ipv6"
}

// FileSpec describes a file-access event payload.
type FileSpec struct {
	Filename string `yaml:"filename,omitempty"`
	FDName   string `yaml:"fd_name,omitempty"` // fd-enriched path (issue #47)
	Flags    int32  `yaml:"flags,omitempty"`
	Mode     uint32 `yaml:"mode,omitempty"`
	Op       string `yaml:"op,omitempty"` // "open", "read", "write"
}

// DNSSpec describes a DNS-query event payload.
type DNSSpec struct {
	QName string `yaml:"qname"`
	QType uint16 `yaml:"qtype,omitempty"`
	RCode uint16 `yaml:"rcode,omitempty"`
}

// PrivescSpec describes a privilege-escalation event payload.
// Use either the named caps_gained/caps_lost helpers or raw bitmasks.
type PrivescSpec struct {
	// CapsGained lists capability names that were newly acquired, e.g. ["CAP_SYS_ADMIN"].
	// Translated to NewCaps = OldCaps | (bits for listed caps).
	CapsGained []string `yaml:"caps_gained,omitempty"`
	// CapsLost lists capability names that were dropped.
	CapsLost []string `yaml:"caps_lost,omitempty"`
	// OldCaps / NewCaps are raw bitmasks. When CapsGained/CapsLost are used,
	// these are computed automatically (OldCaps defaults to 0).
	OldCaps uint64 `yaml:"old_caps,omitempty"`
	NewCaps uint64 `yaml:"new_caps,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Event builder
// ─────────────────────────────────────────────────────────────────────────────

// Build converts an EventSpec into a types.Event ready for rule evaluation.
func (s EventSpec) Build() (types.Event, error) {
	e := types.Event{
		PID:  s.PID,
		TGID: s.TGID,
		UID:  s.UID,
	}
	if e.PID == 0 {
		e.PID = 1
	}
	if s.Comm != "" {
		copy(e.Comm[:], s.Comm)
	}

	switch strings.ToLower(s.Type) {
	case "syscall":
		e.Type = types.EventSyscall
		if s.Syscall == nil {
			return e, fmt.Errorf("event type 'syscall' requires a 'syscall:' block")
		}
		se := &types.SyscallEvent{
			Nr:  s.Syscall.NR,
			Ret: s.Syscall.Ret,
		}
		for i, v := range s.Syscall.Args {
			if i >= len(se.Args) {
				break
			}
			se.Args[i] = v
		}
		e.Syscall = se

	case "network", "tcp_connect":
		e.Type = types.EventTCPConnect
		if s.Network == nil {
			return e, fmt.Errorf("event type 'network' requires a 'network:' block")
		}
		ne := &types.NetworkEvent{
			Sport: s.Network.Sport,
			Dport: s.Network.Dport,
			Proto: 6, // TCP
		}
		switch strings.ToLower(s.Network.Family) {
		case "ipv6":
			ne.Family = types.AFInet6
		default:
			ne.Family = types.AFInet
		}
		if s.Network.SrcIP != "" {
			if err := parseIP(s.Network.SrcIP, ne.Saddr[:], ne.Family); err != nil {
				return e, fmt.Errorf("src_ip: %w", err)
			}
		}
		if s.Network.DstIP != "" {
			if err := parseIP(s.Network.DstIP, ne.Daddr[:], ne.Family); err != nil {
				return e, fmt.Errorf("dst_ip: %w", err)
			}
		}
		e.Network = ne

	case "file", "file_access":
		e.Type = types.EventFileAccess
		fe := &types.FileEvent{}
		if s.File != nil {
			copy(fe.Filename[:], s.File.Filename)
			fe.FDPath = s.File.FDName
			if fe.FDPath == "" {
				fe.FDPath = s.File.Filename
			}
			fe.Flags = s.File.Flags
			fe.Mode = s.File.Mode
			switch strings.ToLower(s.File.Op) {
			case "read":
				fe.Op = 1
			case "write":
				fe.Op = 2
			default: // "open" or empty
				fe.Op = 0
			}
		}
		e.File = fe

	case "dns":
		e.Type = types.EventDNS
		if s.DNS == nil {
			return e, fmt.Errorf("event type 'dns' requires a 'dns:' block")
		}
		e.DNS = &types.DNSEvent{
			QName: s.DNS.QName,
			QType: s.DNS.QType,
			RCode: s.DNS.RCode,
		}

	case "privesc":
		e.Type = types.EventPrivesc
		pe := &types.PrivescEvent{}
		if s.Privesc != nil {
			pe.OldCaps = s.Privesc.OldCaps
			pe.NewCaps = s.Privesc.NewCaps
			for _, name := range s.Privesc.CapsGained {
				bit, ok := capBit(strings.ToUpper(name))
				if !ok {
					return e, fmt.Errorf("unknown capability %q", name)
				}
				pe.NewCaps |= 1 << bit
			}
			for _, name := range s.Privesc.CapsLost {
				bit, ok := capBit(strings.ToUpper(name))
				if !ok {
					return e, fmt.Errorf("unknown capability %q", name)
				}
				pe.OldCaps |= 1 << bit
			}
		}
		e.Privesc = pe

	case "tls":
		e.Type = types.EventTLS
		te := &types.TLSEvent{}
		if s.TLS != nil {
			copy(te.Data[:], s.TLS.Data)
			if s.TLS.DataLen > 0 {
				te.DataLen = s.TLS.DataLen
			} else {
				te.DataLen = uint32(len(s.TLS.Data))
			}
			switch strings.ToLower(s.TLS.Direction) {
			case "read":
				te.Direction = types.TLSDirectionRead
			default:
				te.Direction = types.TLSDirectionWrite
			}
		}
		e.TLS = te

	default:
		return e, fmt.Errorf("unknown event type %q (valid: syscall, network, file, dns, privesc, tls)", s.Type)
	}
	return e, nil
}

// parseIP encodes an IP address string into dst (16-byte big-endian slice).
func parseIP(addr string, dst []byte, family types.AddressFamily) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid IP address %q", addr)
	}
	if family == types.AFInet6 {
		ip16 := ip.To16()
		if ip16 == nil {
			return fmt.Errorf("cannot encode %q as IPv6", addr)
		}
		copy(dst, ip16)
	} else {
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("cannot encode %q as IPv4", addr)
		}
		binary.BigEndian.PutUint32(dst[:4], binary.BigEndian.Uint32(ip4))
	}
	return nil
}

// capBit maps a capability name to its Linux bit index.
var capBitByName = map[string]uint{
	"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2,
	"CAP_FOWNER": 3, "CAP_FSETID": 4, "CAP_KILL": 5,
	"CAP_SETGID": 6, "CAP_SETUID": 7, "CAP_SETPCAP": 8,
	"CAP_LINUX_IMMUTABLE": 9, "CAP_NET_BIND_SERVICE": 10, "CAP_NET_BROADCAST": 11,
	"CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13, "CAP_IPC_LOCK": 14,
	"CAP_IPC_OWNER": 15, "CAP_SYS_MODULE": 16, "CAP_SYS_RAWIO": 17,
	"CAP_SYS_CHROOT": 18, "CAP_SYS_PTRACE": 19, "CAP_SYS_PACCT": 20,
	"CAP_SYS_ADMIN": 21, "CAP_SYS_BOOT": 22, "CAP_SYS_NICE": 23,
	"CAP_SYS_RESOURCE": 24, "CAP_SYS_TIME": 25, "CAP_SYS_TTY_CONFIG": 26,
	"CAP_MKNOD": 27, "CAP_LEASE": 28, "CAP_AUDIT_WRITE": 29,
	"CAP_AUDIT_CONTROL": 30, "CAP_SETFCAP": 31, "CAP_MAC_OVERRIDE": 32,
	"CAP_MAC_ADMIN": 33, "CAP_SYSLOG": 34, "CAP_WAKE_ALARM": 35,
	"CAP_BLOCK_SUSPEND": 36, "CAP_AUDIT_READ": 37, "CAP_PERFMON": 38,
	"CAP_BPF": 39, "CAP_CHECKPOINT_RESTORE": 40,
}

func capBit(name string) (uint, bool) {
	v, ok := capBitByName[name]
	return v, ok
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML loader
// ─────────────────────────────────────────────────────────────────────────────

// LoadSuite parses a *_test.yaml file and returns the Suite.
// path is used to resolve relative RulesPath values.
func LoadSuite(path string) (Suite, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Suite{}, "", fmt.Errorf("ruletest: read %s: %w", path, err)
	}
	var s Suite
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Suite{}, "", fmt.Errorf("ruletest: parse %s: %w", path, err)
	}
	if s.Suite == "" {
		s.Suite = strings.TrimSuffix(filepath.Base(path), "_test.yaml")
		s.Suite = strings.TrimSuffix(s.Suite, ".yaml")
	}
	// Resolve RulesPath relative to the test file.
	resolvedRulesPath := ""
	if s.RulesPath != "" {
		if filepath.IsAbs(s.RulesPath) {
			resolvedRulesPath = s.RulesPath
		} else {
			resolvedRulesPath = filepath.Join(filepath.Dir(path), s.RulesPath)
		}
	}
	return s, resolvedRulesPath, nil
}
