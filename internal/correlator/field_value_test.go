package correlator

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func allFieldNames() []string {
	names := map[string]bool{}
	for n := range fieldIDByName {
		names[n] = true
	}
	// поля, которые код ByID не разбирает и отдаёт строковой версии, плюс чужие
	for _, n := range []string{"qname", "dns.qname", "qtype", "rcode", "direction", "qname_length", "qname_entropy",
		"qname_max_label_entropy", "tls_data", "data", "data_len", "ja3", "caps", "duration_sec", "gpu_op",
		"cloud.provider", "name", "from_tmpfs", "fd", "cmd", "no_such_field", ""} {
		names[n] = true
	}
	var out []string
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func fieldCorpus() []types.Event {
	var evs []types.Event
	comm := func(e *types.Event, c string) { copy(e.Comm[:], c); copy(e.ParentComm[:], "parent-"+c) }
	for t := types.EventType(0); t <= 17; t++ {
		base := types.Event{Type: t, PID: 4242, PPID: 77, UID: 1000, ProcArgs: "x --y", CgroupID: 9, UnitCgroupID: 9}
		comm(&base, "bash")
		evs = append(evs, base) // без вложенных структур
		for _, enrich := range []*types.EnrichmentInfo{nil, {PodName: "p", Namespace: "ns", ContainerID: "c"}} {
			e := base
			e.Enrichment = enrich
			e.File = &types.FileEvent{Filename: "/etc/ssh/sshd_config.bak", Flags: 577, Mode: 0o644, Op: 2, FDPath: "/proc/1/fd/3", FDPathTruncated: true}
			e.Syscall = &types.SyscallEvent{Nr: 59, Ret: -2, Args: [6]uint64{1, 2, 3, 4, 5, 18446744073709551615}}
			e.Network = &types.NetworkEvent{Dport: 4444, Sport: 5555, Proto: 6, Family: types.AFInet, Daddr: [16]byte{10, 1, 2, 3}}
			e.DNS = &types.DNSEvent{QName: "abc.example.com", QType: 1}
			e.TLS = &types.TLSEvent{}
			e.ProcArgsTruncated = true
			evs = append(evs, e)
			e6 := e
			e6.Network = &types.NetworkEvent{Dport: 443, Family: types.AFInet6, Daddr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}}
			e6.File = &types.FileEvent{Filename: "noslash", Op: 99}
			e6.Syscall = &types.SyscallEvent{Nr: 9999}
			evs = append(evs, e6)
			eNoDot := e
			eNoDot.File = &types.FileEvent{Filename: "/a/b/c", Op: 0}
			eNoDot.Syscall = &types.SyscallEvent{Nr: -1}
			evs = append(evs, eNoDot)
		}
		// тип с обнулёнными вложенными структурами при заданном типе — путь «nil → пусто»
		for _, nilE := range []types.Event{{Type: t}} {
			evs = append(evs, nilE)
		}
	}
	return evs
}

// П4: getFieldValueByID ≡ getFieldValueNorm — все поля × все типы × варианты структур.
func TestFieldValueByIDMatchesNorm(t *testing.T) {
	re := NewRuleEngine(nil)
	n := 0
	for _, e := range fieldCorpus() {
		e := e
		for _, name := range allFieldNames() {
			cache1, cache2 := &eventFieldCache{}, &eventFieldCache{}
			want := re.getFieldValueNorm(&e, name, nil, cache1)
			got := re.getFieldValueByID(&e, fieldIDOf(name), name, nil, cache2)
			require.Equal(t, want, got, "type=%v field=%q", e.Type, name)
			// без кэша тоже
			require.Equal(t, re.getFieldValueNorm(&e, name, nil, nil), re.getFieldValueByID(&e, fieldIDOf(name), name, nil, nil), "nocache type=%v field=%q", e.Type, name)
			n++
		}
	}
	require.Greater(t, n, 5000)
}

// На дампе idle (если задан W87_DUMP): те же значения для всех полей на каждом 7-м событии.
func TestFieldValueByIDMatchesNormOnDump(t *testing.T) {
	p := os.Getenv("W87_DUMP")
	if p == "" {
		t.Skip()
	}
	evs, err := LoadEventDump(p)
	require.NoError(t, err)
	re := NewRuleEngine(nil)
	names := allFieldNames()
	for i := 0; i < len(evs); i += 7 {
		e := &evs[i]
		for _, name := range names {
			require.Equal(t, re.getFieldValueNorm(e, name, nil, &eventFieldCache{}), re.getFieldValueByID(e, fieldIDOf(name), name, nil, &eventFieldCache{}), "ev=%d type=%v field=%q", i, e.Type, name)
		}
	}
}

// Мутация: если ByID теряет ветку (например, flags), корпус краснеет.
func TestFieldValueByIDCoversHotFields(t *testing.T) {
	hot := map[types.EventType][]string{
		types.EventFileAccess: {"filename", "fd.name", "flags", "mode", "op", "directory", "extension", "comm", "uid", "pid", "ppid", "parent_comm", "proc.args"},
		types.EventSyscall:    {"nr", "ret", "arg0", "arg5", "comm", "uid", "fd.name", "proc.args", "pid"},
		types.EventTCPConnect: {"dport", "sport", "daddr", "saddr", "proto", "family", "comm", "uid", "ppid"},
	}
	for typ, fs := range hot {
		for _, f := range fs {
			id := fieldIDOf(f)
			require.NotEqual(t, fidOther, id, "поле %s типа %v не имеет кода — П4 его не ускорит", f, typ)
		}
	}
}
