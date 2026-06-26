package bpf

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func comm16(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func TestPrivescRawEvent_ToTypesEvent(t *testing.T) {
	raw := &PrivescRawEvent{
		Timestamp: 111, PID: 1, TGID: 2, PPID: 3, UID: 4,
		Comm: comm16("evil"), ParentComm: comm16("bash"),
		OldCaps: 0b01, NewCaps: 0b11,
	}
	e := raw.ToTypesEvent()
	assert.Equal(t, types.EventPrivesc, e.Type)
	assert.Equal(t, uint64(111), e.Timestamp)
	assert.Equal(t, uint32(1), e.PID)
	require.NotNil(t, e.Privesc)
	assert.Equal(t, uint64(0b01), e.Privesc.OldCaps)
	assert.Equal(t, uint64(0b11), e.Privesc.NewCaps)
}

func TestNetworkCloseRawEvent_ToTypesEvent(t *testing.T) {
	raw := &NetworkCloseRawEvent{
		Timestamp: 1, PID: 10, Comm: comm16("curl"),
		Sport: 1234, Dport: 443, Family: 2, DurationNs: uint64(5 * time.Second),
	}
	e := raw.ToTypesEvent()
	assert.Equal(t, types.EventNetClose, e.Type)
	require.NotNil(t, e.NetClose)
	assert.Equal(t, uint16(443), e.NetClose.Dport)
	assert.Equal(t, 5*time.Second, e.NetClose.Duration)
}

func TestKmodRawEvent_ToTypesEvent(t *testing.T) {
	var name [64]byte
	copy(name[:], "evil_mod")
	raw := &KmodRawEvent{Timestamp: 2, PID: 11, Comm: comm16("insmod"), ModName: name, FromTmpfs: 1}
	e := raw.ToTypesEvent()
	assert.Equal(t, types.EventKmodLoad, e.Type)
	require.NotNil(t, e.Kmod)
	assert.Equal(t, "evil_mod", e.Kmod.ModName, "null bytes must be trimmed")
	assert.True(t, e.Kmod.FromTmpfs)
}

func TestCgroupEscapeRawEvent_ToTypesEvent(t *testing.T) {
	raw := &CgroupEscapeRawEvent{Timestamp: 3, PID: 12, Comm: comm16("runc"), InitCgroupID: 100, NewCgroupID: 200}
	e := raw.ToTypesEvent()
	assert.Equal(t, types.EventCgroupEsc, e.Type)
	require.NotNil(t, e.CgroupEsc)
	assert.Equal(t, uint64(100), e.CgroupEsc.InitCgroupID)
	assert.Equal(t, uint64(200), e.CgroupEsc.NewCgroupID)
}

func TestIOUringRawEvent_ToTypesEvent(t *testing.T) {
	raw := &IOUringRawEvent{Timestamp: 4, PID: 13, Comm: comm16("app"), Op: 7, Flags: 1, Fd: 9, ToSubmit: 3}
	e := raw.ToTypesEvent()
	assert.Equal(t, types.EventIOUring, e.Type)
	require.NotNil(t, e.IOUring)
	assert.Equal(t, uint8(7), e.IOUring.Op)
	assert.Equal(t, int32(9), e.IOUring.Fd)
	assert.Equal(t, uint32(3), e.IOUring.ToSubmit)
}

func TestBpfMonitorRawEvent_ToTypesEvent(t *testing.T) {
	raw := &BpfMonitorRawEvent{Timestamp: 5, PID: 14, Comm: comm16("loader"), Cmd: 5, ProgType: 2, Ret: -1}
	e := raw.ToTypesEvent()
	assert.Equal(t, types.EventBPFProgram, e.Type)
	require.NotNil(t, e.BPFProgram)
	assert.Equal(t, uint32(5), e.BPFProgram.Cmd)
	assert.Equal(t, uint32(2), e.BPFProgram.ProgType)
	assert.Equal(t, int32(-1), e.BPFProgram.Ret)
}
