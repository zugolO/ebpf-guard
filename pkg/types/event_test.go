package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestBPFCmdName(t *testing.T) {
	cases := []struct {
		cmd  uint32
		want string
	}{
		{BPFCmdMapCreate, "MAP_CREATE"},
		{BPFCmdMapLookup, "MAP_LOOKUP_ELEM"},
		{BPFCmdMapUpdate, "MAP_UPDATE_ELEM"},
		{BPFCmdMapDelete, "MAP_DELETE_ELEM"},
		{BPFCmdMapGetNextKey, "MAP_GET_NEXT_KEY"},
		{BPFCmdProgLoad, "PROG_LOAD"},
		{BPFCmdObjPin, "OBJ_PIN"},
		{BPFCmdObjGet, "OBJ_GET"},
		{BPFCmdProgAttach, "PROG_ATTACH"},
		{BPFCmdProgDetach, "PROG_DETACH"},
		{99, "BPF_CMD_99"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, BPFCmdName(tc.cmd), "cmd=%d", tc.cmd)
	}
}

func TestBPFCmdConstants(t *testing.T) {
	// Verify the command numbers match the kernel's bpf_cmd enum.
	assert.Equal(t, uint32(0), BPFCmdMapCreate)
	assert.Equal(t, uint32(1), BPFCmdMapLookup)
	assert.Equal(t, uint32(2), BPFCmdMapUpdate)
	assert.Equal(t, uint32(3), BPFCmdMapDelete)
	assert.Equal(t, uint32(4), BPFCmdMapGetNextKey)
	assert.Equal(t, uint32(5), BPFCmdProgLoad)
	assert.Equal(t, uint32(6), BPFCmdObjPin)
	assert.Equal(t, uint32(7), BPFCmdObjGet)
	assert.Equal(t, uint32(8), BPFCmdProgAttach)
	assert.Equal(t, uint32(9), BPFCmdProgDetach)
}

func TestBPFProgTypeName(t *testing.T) {
	cases := []struct {
		t    uint32
		want string
	}{
		{0, "SOCKET_FILTER"},
		{15, "KPROBE"},
		{26, "LSM"},
		{31, "SK_LOOKUP"},
		{1234, "UNKNOWN_1234"}, // not in the table
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, BPFProgTypeName(tc.t), "progType=%d", tc.t)
	}
}

func TestEventType_UnmarshalYAML_Numeric(t *testing.T) {
	var doc struct {
		EventType EventType `yaml:"event_type"`
	}
	require.NoError(t, yaml.Unmarshal([]byte("event_type: 3\n"), &doc))
	assert.Equal(t, EventFileAccess, doc.EventType)
}

func TestEventType_UnmarshalYAML_String(t *testing.T) {
	cases := map[string]EventType{
		"file":          EventFileAccess,
		"FILE":          EventFileAccess, // case-insensitive
		"network":       EventTCPConnect,
		"tcp_connect":   EventTCPConnect, // alias
		"dns":           EventDNS,
		"bpf_prog_load": EventBPFProgram, // alias
		"io_uring":      EventIOUring,
	}
	for in, want := range cases {
		var doc struct {
			EventType EventType `yaml:"event_type"`
		}
		require.NoError(t, yaml.Unmarshal([]byte("event_type: "+in+"\n"), &doc), "input=%q", in)
		assert.Equal(t, want, doc.EventType, "input=%q", in)
	}
}

func TestEventType_UnmarshalYAML_Unknown(t *testing.T) {
	var doc struct {
		EventType EventType `yaml:"event_type"`
	}
	err := yaml.Unmarshal([]byte("event_type: not_a_real_type\n"), &doc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event_type")
}

func TestEvent_Reset(t *testing.T) {
	e := &Event{
		Type:              EventSyscall,
		PID:               1234,
		Syscall:           &SyscallEvent{},
		Network:           &NetworkEvent{},
		DNS:               &DNSEvent{},
		TLS:               &TLSEvent{},
		ProcArgs:          "/bin/sh -c id",
		ProcArgsTruncated: true,
	}

	e.Reset()

	// All pointer fields must be nil'd so the pooled Event releases inner structs.
	assert.Nil(t, e.Syscall)
	assert.Nil(t, e.Network)
	assert.Nil(t, e.DNS)
	assert.Nil(t, e.TLS)
	assert.Nil(t, e.File)
	assert.Nil(t, e.Privesc)
	assert.Nil(t, e.NetClose)
	assert.Nil(t, e.Kmod)
	assert.Nil(t, e.CgroupEsc)
	assert.Nil(t, e.GPU)
	assert.Nil(t, e.CloudAudit)
	assert.Nil(t, e.IOUring)
	assert.Nil(t, e.BPFProgram)
	// String args cleared too.
	assert.Empty(t, e.ProcArgs)
	assert.False(t, e.ProcArgsTruncated)
}

func TestEventTypeString(t *testing.T) {
	assert.Equal(t, "syscall", EventSyscall.String())
	assert.Equal(t, "tcp_connect", EventTCPConnect.String())
	assert.Equal(t, "net_close", EventNetClose.String())
	assert.Equal(t, "bpf_program", EventBPFProgram.String())
	assert.Equal(t, "unknown", EventType(9999).String())

	// Every declared EventType must have a canonical (non-"unknown") name so a
	// new type can't silently fall through to a placeholder label.
	for et := EventSyscall; et <= EventBPFProgram; et++ {
		assert.NotEqual(t, "unknown", et.String(), "EventType %d needs a canonical name", et)
	}
}
