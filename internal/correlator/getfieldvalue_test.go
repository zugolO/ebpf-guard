package correlator

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func mkComm(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func mkFilename(s string) [256]byte {
	var b [256]byte
	copy(b[:], s)
	return b
}

// TestGetFieldValue exercises the per-event-type field extraction switch.
func TestGetFieldValue(t *testing.T) {
	re := NewRuleEngine(nil)

	v4 := [16]byte{8, 8, 8, 8}

	cases := []struct {
		name  string
		event types.Event
		field string
		want  string
	}{
		// Network (TCP connect)
		{"net dport", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Dport: 443}}, "dport", "443"},
		{"net sport", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Sport: 1234}}, "sport", "1234"},
		{"net daddr v4", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Daddr: v4, Family: types.AFInet}}, "daddr", "8.8.8.8"},
		{"net family v4", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Family: types.AFInet}}, "family", "ipv4"},
		{"net family v6", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Family: types.AFInet6}}, "family", "ipv6"},
		{"net proto", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Proto: 6}}, "proto", "6"},
		{"net comm", types.Event{Type: types.EventTCPConnect, Comm: mkComm("curl"), Network: &types.NetworkEvent{}}, "comm", "curl"},
		{"net alias network.dport", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Dport: 80}}, "network.dport", "80"},
		{"net nil", types.Event{Type: types.EventTCPConnect}, "dport", ""},

		// File access
		{"file filename", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Filename: mkFilename("/etc/passwd")}}, "filename", "/etc/passwd"},
		{"file alias file.path", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Filename: mkFilename("/etc/shadow")}}, "file.path", "/etc/shadow"},
		{"file op open", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Op: 0}}, "op", "open"},
		{"file op write", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Op: 2}}, "op", "write"},
		{"file directory", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Filename: mkFilename("/var/log/syslog")}}, "directory", "/var/log"},
		{"file extension", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Filename: mkFilename("/tmp/x.sh")}}, "extension", ".sh"},
		{"file flags", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Flags: 577}}, "flags", "577"},
		{"file mode", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Mode: 420}}, "mode", "420"},

		// Syscall
		{"syscall ret", types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Ret: -1}}, "ret", "-1"},
		{"syscall arg0", types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Args: [6]uint64{42}}}, "arg0", "42"},
		{"syscall arg5", types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Args: [6]uint64{0, 0, 0, 0, 0, 99}}}, "arg5", "99"},
		{"syscall uid", types.Event{Type: types.EventSyscall, UID: 1000, Syscall: &types.SyscallEvent{}}, "uid", "1000"},

		// DNS
		{"dns qname", types.Event{Type: types.EventDNS, DNS: &types.DNSEvent{QName: "evil.example.com"}}, "qname", "evil.example.com"},
		{"dns qtype", types.Event{Type: types.EventDNS, DNS: &types.DNSEvent{QType: 1}}, "qtype", "1"},
		{"dns rcode", types.Event{Type: types.EventDNS, DNS: &types.DNSEvent{RCode: 3}}, "rcode", "3"},
		{"dns qname_length", types.Event{Type: types.EventDNS, DNS: &types.DNSEvent{QName: "abc"}}, "qname_length", "3"},

		// TLS
		{"tls data_len", types.Event{Type: types.EventTLS, TLS: &types.TLSEvent{DataLen: 100}}, "data_len", "100"},
		{"tls ja3", types.Event{Type: types.EventTLS, TLS: &types.TLSEvent{JA3: "abc123"}}, "ja3", "abc123"},
		{"tls ja4", types.Event{Type: types.EventTLS, TLS: &types.TLSEvent{JA4: "t13d"}}, "ja4", "t13d"},

		// Privesc
		{"privesc uid", types.Event{Type: types.EventPrivesc, UID: 0}, "uid", "0"},
		{"privesc caps", types.Event{Type: types.EventPrivesc, Privesc: &types.PrivescEvent{NewCaps: 0x21}}, "caps", "0x21"},

		// NetClose
		{"netclose dport", types.Event{Type: types.EventNetClose, NetClose: &types.NetworkCloseEvent{Dport: 8443}}, "dport", "8443"},
		{"netclose family", types.Event{Type: types.EventNetClose, NetClose: &types.NetworkCloseEvent{Family: types.AFInet}}, "family", "ipv4"},

		// GPU
		{"gpu op", types.Event{Type: types.EventGPU, GPU: &types.GPUEvent{Op: 0}}, "gpu_op", "alloc"},
		{"gpu size", types.Event{Type: types.EventGPU, GPU: &types.GPUEvent{Size: 4096}}, "gpu_size", "4096"},

		// CloudAudit
		{"cloud provider", types.Event{Type: types.EventCloudAudit, CloudAudit: &types.CloudAuditEvent{Provider: "aws"}}, "cloud.provider", "aws"},
		{"cloud action", types.Event{Type: types.EventCloudAudit, CloudAudit: &types.CloudAuditEvent{Action: "AssumeRole"}}, "cloud.action", "AssumeRole"},

		// Kmod
		{"kmod name", types.Event{Type: types.EventKmodLoad, Kmod: &types.KmodEvent{ModName: "rootkit"}}, "name", "rootkit"},
		{"kmod from_tmpfs", types.Event{Type: types.EventKmodLoad, Kmod: &types.KmodEvent{FromTmpfs: true}}, "from_tmpfs", "true"},

		// IOUring
		{"iouring op setup", types.Event{Type: types.EventIOUring, IOUring: &types.IOUringEvent{Op: 0}}, "op", "setup"},
		{"iouring op enter", types.Event{Type: types.EventIOUring, IOUring: &types.IOUringEvent{Op: 1}}, "op", "enter"},
		{"iouring fd", types.Event{Type: types.EventIOUring, IOUring: &types.IOUringEvent{Fd: 7}}, "fd", "7"},

		// BPF program
		{"bpf cmd_nr", types.Event{Type: types.EventBPFProgram, BPFProgram: &types.BPFProgramEvent{Cmd: 5}}, "cmd_nr", "5"},
		{"bpf ret", types.Event{Type: types.EventBPFProgram, BPFProgram: &types.BPFProgramEvent{Ret: -13}}, "ret", "-13"},

		// LSM audit (ai_sandbox decisions — issue #268)
		{"lsm decision deny", types.Event{Type: types.EventLSMAudit, LSMAudit: &types.LSMAuditEvent{Decision: "sandbox_deny"}}, "decision", "sandbox_deny"},
		{"lsm hook", types.Event{Type: types.EventLSMAudit, LSMAudit: &types.LSMAuditEvent{Hook: "file_open"}}, "hook", "file_open"},
		{"lsm path", types.Event{Type: types.EventLSMAudit, LSMAudit: &types.LSMAuditEvent{Path: "/etc/shadow"}}, "path", "/etc/shadow"},
		{"lsm target_pid", types.Event{Type: types.EventLSMAudit, LSMAudit: &types.LSMAuditEvent{TargetPID: 99}}, "target_pid", "99"},
		{"lsm comm", types.Event{Type: types.EventLSMAudit, Comm: mkComm("claude"), LSMAudit: &types.LSMAuditEvent{}}, "comm", "claude"},
		{"lsm uid", types.Event{Type: types.EventLSMAudit, UID: 1000, LSMAudit: &types.LSMAuditEvent{}}, "uid", "1000"},
		{"lsm nil", types.Event{Type: types.EventLSMAudit}, "decision", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := re.getFieldValue(tc.event, tc.field, nil)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCapNameToBit(t *testing.T) {
	bit, ok := capNameToBit("CAP_SYS_ADMIN")
	assert.True(t, ok)
	assert.Equal(t, uint(21), bit)

	// Case-insensitive.
	bit, ok = capNameToBit("cap_net_raw")
	assert.True(t, ok)
	assert.Equal(t, uint(13), bit)

	_, ok = capNameToBit("CAP_NOT_A_REAL_CAP")
	assert.False(t, ok)
}

func TestMatchesCaps(t *testing.T) {
	re := NewRuleEngine(nil)

	// Gained CAP_SYS_ADMIN (bit 21).
	gained := types.Event{Type: types.EventPrivesc, Privesc: &types.PrivescEvent{
		OldCaps: 0,
		NewCaps: 1 << 21,
	}}
	assert.True(t, re.matchesCaps(gained, []string{"CAP_SYS_ADMIN"}, true))
	assert.False(t, re.matchesCaps(gained, []string{"CAP_SYS_ADMIN"}, false))
	assert.False(t, re.matchesCaps(gained, []string{"CAP_NET_RAW"}, true))

	// Dropped CAP_NET_RAW (bit 13).
	dropped := types.Event{Type: types.EventPrivesc, Privesc: &types.PrivescEvent{
		OldCaps: 1 << 13,
		NewCaps: 0,
	}}
	assert.True(t, re.matchesCaps(dropped, []string{"CAP_NET_RAW"}, false))

	// No privesc payload → never matches.
	assert.False(t, re.matchesCaps(types.Event{Type: types.EventPrivesc}, []string{"CAP_SYS_ADMIN"}, true))
}
