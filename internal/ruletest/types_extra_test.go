package ruletest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// EventSpec.Build — additional branch coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestEventSpec_Build_Syscall_ArgsOverflow(t *testing.T) {
	spec := EventSpec{
		Type: "syscall",
		Syscall: &SyscallSpec{
			NR:   1,
			Args: []uint64{1, 2, 3, 4, 5, 6, 7}, // se.Args is [6]uint64; the 7th must be dropped, not panic.
		},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.Syscall)
	assert.Equal(t, uint64(6), event.Syscall.Args[5])
}

func TestEventSpec_Build_Network_MissingBlock(t *testing.T) {
	spec := EventSpec{Type: "network"}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'network:' block")
}

func TestEventSpec_Build_Network_IPv6(t *testing.T) {
	spec := EventSpec{
		Type: "network",
		Network: &NetworkSpec{
			Family: "ipv6",
			SrcIP:  "2001:db8::1",
			DstIP:  "2001:db8::2",
			Dport:  443,
		},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.Network)
	assert.Equal(t, types.AFInet6, event.Network.Family)
}

func TestEventSpec_Build_Network_BadSrcIP(t *testing.T) {
	spec := EventSpec{
		Type:    "network",
		Network: &NetworkSpec{SrcIP: "not-an-ip", Dport: 80},
	}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "src_ip")
}

func TestEventSpec_Build_Network_IPv6AddrOverIPv4Family(t *testing.T) {
	spec := EventSpec{
		Type:    "network",
		Network: &NetworkSpec{DstIP: "::1"}, // Family defaults to ipv4, ::1 has no IPv4 form.
	}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "as IPv4")
}

func TestEventSpec_Build_File_ReadOp(t *testing.T) {
	spec := EventSpec{
		Type: "file",
		File: &FileSpec{Filename: "/etc/shadow", Op: "read"},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.File)
	assert.Equal(t, uint8(1), event.File.Op)
}

func TestEventSpec_Build_File_OpenOp(t *testing.T) {
	spec := EventSpec{
		Type: "file",
		File: &FileSpec{Filename: "/etc/hosts", Op: "open"},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.File)
	assert.Equal(t, uint8(0), event.File.Op)
}

func TestEventSpec_Build_File_NilBlock(t *testing.T) {
	spec := EventSpec{Type: "file"}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.File)
}

func TestEventSpec_Build_DNS_MissingBlock(t *testing.T) {
	spec := EventSpec{Type: "dns"}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'dns:' block")
}

func TestEventSpec_Build_Privesc_UnknownCapGained(t *testing.T) {
	spec := EventSpec{
		Type:    "privesc",
		Privesc: &PrivescSpec{CapsGained: []string{"CAP_NOT_A_REAL_CAP"}},
	}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown capability")
}

func TestEventSpec_Build_Privesc_UnknownCapLost(t *testing.T) {
	spec := EventSpec{
		Type:    "privesc",
		Privesc: &PrivescSpec{CapsLost: []string{"CAP_NOT_A_REAL_CAP"}},
	}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown capability")
}

func TestEventSpec_Build_Privesc_CapsLost(t *testing.T) {
	spec := EventSpec{
		Type:    "privesc",
		Privesc: &PrivescSpec{CapsLost: []string{"CAP_NET_ADMIN"}},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.Privesc)
	assert.Equal(t, uint64(1<<12), event.Privesc.OldCaps) // CAP_NET_ADMIN = bit 12
}

func TestEventSpec_Build_Privesc_NilBlock(t *testing.T) {
	spec := EventSpec{Type: "privesc"}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.Privesc)
}

func TestEventSpec_Build_TLS_WriteDefaultDataLen(t *testing.T) {
	spec := EventSpec{
		Type: "tls",
		TLS:  &TLSSpec{Data: "GET / HTTP/1.1"},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.TLS)
	assert.Equal(t, types.TLSDirectionWrite, event.TLS.Direction)
	assert.Equal(t, uint32(len("GET / HTTP/1.1")), event.TLS.DataLen)
}

func TestEventSpec_Build_TLS_ReadExplicitDataLen(t *testing.T) {
	spec := EventSpec{
		Type: "tls",
		TLS:  &TLSSpec{Data: "hello", DataLen: 100, Direction: "read"},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.TLS)
	assert.Equal(t, types.TLSDirectionRead, event.TLS.Direction)
	assert.Equal(t, uint32(100), event.TLS.DataLen)
}

func TestEventSpec_Build_TLS_NilBlock(t *testing.T) {
	spec := EventSpec{Type: "tls"}
	event, err := spec.Build()
	require.NoError(t, err)
	require.NotNil(t, event.TLS)
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadSuite — error branches and default naming
// ─────────────────────────────────────────────────────────────────────────────

func TestLoadSuite_MissingFile(t *testing.T) {
	_, _, err := LoadSuite(filepath.Join(t.TempDir(), "nope_test.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read")
}

func TestLoadSuite_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_test.yaml")
	require.NoError(t, os.WriteFile(path, []byte("suite: [this is not valid: yaml"), 0o600))

	_, _, err := LoadSuite(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestLoadSuite_DefaultNameFromFilename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "my_cool_suite_test.yaml")
	require.NoError(t, os.WriteFile(path, []byte("tests: []\n"), 0o600))

	suite, _, err := LoadSuite(path)
	require.NoError(t, err)
	assert.Equal(t, "my_cool_suite", suite.Suite)
}
