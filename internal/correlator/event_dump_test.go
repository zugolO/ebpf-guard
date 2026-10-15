package correlator

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func dumpSampleEvents() []types.Event {
	c := func(s string) (b [16]byte) { copy(b[:], s); return }
	var n types.NetworkEvent
	n.Daddr[0], n.Daddr[1], n.Daddr[2], n.Daddr[3] = 10, 0, 7, 255
	n.Saddr[15] = 0xab
	n.Dport, n.Sport, n.Proto, n.Family = 443, 5555, 6, types.AFInet
	return []types.Event{
		{Type: types.EventFileAccess, Timestamp: 5, PID: 11, TGID: 11, PPID: 1, UID: 33, Comm: c("nginx"), ParentComm: c("systemd"),
			CgroupID: 77, UnitCgroupID: 78, ProcArgs: "nginx -g daemon off", ProcArgsTruncated: true,
			File:       &types.FileEvent{Op: 1, Flags: 0o2000000, Mode: 0o644, Filename: "/etc/passwd", FDPath: "/etc/shadow", FDPathTruncated: true},
			Enrichment: &types.EnrichmentInfo{PodName: "p", ContainerID: "cid"}},
		{Type: types.EventSyscall, PID: 12, Comm: c("bash"), Syscall: &types.SyscallEvent{Nr: 59, Ret: -2, Args: [6]uint64{1, 2, 3, 4, 5, 6}}},
		{Type: types.EventTCPConnect, PID: 13, Comm: c("curl"), Network: &n},
		{Type: types.EventDNS, PID: 14, Comm: c("dig"), DNS: &types.DNSEvent{QName: "example.com", QType: 1, ResponseIPs: []string{"1.2.3.4"}}},
	}
}

func TestEventDump_RoundTripKeepsWhatRulesRead(t *testing.T) {
	var buf bytes.Buffer
	stop := enableEventDumpWriter(&buf, nil, 1)
	re := NewRuleEngine(nil)
	in := dumpSampleEvents()
	for _, e := range in {
		re.EvaluateInto(e, func(types.Alert) {})
	}
	require.NoError(t, stop())

	path := filepath.Join(t.TempDir(), "d.jsonl")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	out, err := LoadEventDump(path)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestEventDump_SamplesEveryNth(t *testing.T) {
	var buf bytes.Buffer
	stop := enableEventDumpWriter(&buf, nil, 3)
	re := NewRuleEngine(nil)
	for i := 0; i < 10; i++ {
		re.EvaluateInto(types.Event{Type: types.EventSyscall, PID: uint32(i), Syscall: &types.SyscallEvent{Nr: 1}}, func(types.Alert) {})
	}
	w, e := EventDumpStats()
	require.NoError(t, stop())
	require.Equal(t, uint64(3), w, "из 10 событий при every=3 — 3, 6, 9-е")
	require.Zero(t, e)
	require.Equal(t, 3, strings.Count(buf.String(), "\n"))
	require.Contains(t, buf.String(), `"pid":2,`)
}

func TestEventDump_OffWritesNothingAndStopDisables(t *testing.T) {
	require.Nil(t, eventDump.Load(), "по умолчанию выключено")
	var buf bytes.Buffer
	stop := enableEventDumpWriter(&buf, nil, 1)
	require.NoError(t, stop())
	require.Nil(t, eventDump.Load())
	NewRuleEngine(nil).EvaluateInto(dumpSampleEvents()[0], func(types.Alert) {})
	require.Zero(t, buf.Len())
}

func TestEventDump_FileMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.jsonl")
	stop, err := EnableEventDump(path, 1)
	require.NoError(t, err)
	require.NoError(t, stop())
	st, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}

// Дамп не меняет детект: алерты на оригинале и на событиях, прошедших дамп,
// совпадают на всём наборе правил.
func TestEventDump_ReplayGivesSameAlerts(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)
	collect := func(evs []types.Event) []string {
		var ids []string
		for _, e := range evs {
			re.EvaluateInto(e, func(a types.Alert) { ids = append(ids, a.RuleID) })
		}
		sort.Strings(ids)
		return ids
	}
	in := dumpSampleEvents()
	in = append(in, types.Event{Type: types.EventFileAccess, PID: 1, Comm: [16]byte{'c', 'a', 't'},
		File: &types.FileEvent{Op: 0, Filename: "/etc/shadow", Flags: 0}})
	want := collect(in)
	require.NotEmpty(t, want, "фикстура должна давать хотя бы один алерт")

	var buf bytes.Buffer
	stop := enableEventDumpWriter(&buf, nil, 1)
	for _, e := range in {
		re.EvaluateInto(e, func(types.Alert) {})
	}
	require.NoError(t, stop())
	path := filepath.Join(t.TempDir(), "d.jsonl")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	out, err := LoadEventDump(path)
	require.NoError(t, err)
	require.Equal(t, want, collect(out))
}

func BenchmarkEvaluateInto_DumpOff(b *testing.B) {
	re := NewRuleEngine(nil)
	e := dumpSampleEvents()[0]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re.EvaluateInto(e, func(types.Alert) {})
	}
}
