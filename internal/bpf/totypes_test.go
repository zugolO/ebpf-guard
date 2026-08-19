package bpf

import (
	"fmt"
	"os"
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
	assert.Equal(t, types.KtimeToEpoch(111), e.Timestamp)
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

// TestCgroupEscapeRawEvent_ToTypesEvent_NonEmptyCommUntouched hedges the
// non-empty path against the 5.9.1f fallback overwriting a Comm the kernel
// already filled correctly — the fallback must only engage on the torn-read
// case (leading NUL), never override a valid name.
func TestCgroupEscapeRawEvent_ToTypesEvent_NonEmptyCommUntouched(t *testing.T) {
	raw := &CgroupEscapeRawEvent{Timestamp: 3, PID: 4000002, Comm: comm16("runc"), InitCgroupID: 1, NewCgroupID: 2}
	e := raw.ToTypesEvent()
	assert.Equal(t, comm16("runc"), e.Comm)
}

// TestCgroupEscapeRawEvent_ToTypesEvent_EmptyCommDeadPIDStaysEmpty guards the
// 5.9.1f /proc fallback added for bpf/cgroup.bpf.c's torn leader->comm read
// (BPF_CORE_READ on a different task than the one that triggered the LSM
// hook, unsynchronized — same class as 5.9h's parent_comm finding, but here
// it hits the event's own leaf Comm, which is what lands in Alert.Comm).
// A PID this high cannot exist on any Linux host (pid_max is 2^22 at most,
// see lineage_ppidfallback_test.go's TestLookupOwnPPID_CachesNegativeResult
// for the same technique), so /proc/<pid>/comm is guaranteed to miss on
// every platform — the fallback must leave Comm empty, not panic or fabricate
// a name.
func TestCgroupEscapeRawEvent_ToTypesEvent_EmptyCommDeadPIDStaysEmpty(t *testing.T) {
	const deadPID uint32 = 4000000
	raw := &CgroupEscapeRawEvent{Timestamp: 3, PID: deadPID, Comm: [16]byte{}, InitCgroupID: 1, NewCgroupID: 2}
	e := raw.ToTypesEvent()
	assert.Equal(t, [16]byte{}, e.Comm, "no /proc entry for this PID exists — Comm must stay empty, not be fabricated")
}

// TestCgroupEscapeRawEvent_ToTypesEvent_EmptyCommOwnPIDResolves is the
// positive case: on a host with /proc (Linux — CI and ebaka2), an empty Comm
// for a PID that is genuinely alive (this test process itself) must resolve
// to a non-empty name via /proc/<pid>/comm. On platforms without /proc
// (macOS dev) the fallback misses gracefully and this assertion is skipped
// rather than failing on environment, not code.
func TestCgroupEscapeRawEvent_ToTypesEvent_EmptyCommOwnPIDResolves(t *testing.T) {
	pid := uint32(os.Getpid())
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/comm", pid)); err != nil {
		t.Skipf("/proc/%d/comm unavailable on this platform (%v) — fallback path not exercisable here", pid, err)
	}
	raw := &CgroupEscapeRawEvent{Timestamp: 3, PID: pid, Comm: [16]byte{}, InitCgroupID: 1, NewCgroupID: 2}
	e := raw.ToTypesEvent()
	assert.NotEqual(t, [16]byte{}, e.Comm, "a live PID's /proc/<pid>/comm must backfill the torn empty read")
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
