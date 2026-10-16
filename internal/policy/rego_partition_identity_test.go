//go:build rego

package policy

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.7, П5 (№564): тождество решений Rego «узкая партиция против full».
// Алерт типа вне syscall/network/file/dns идёт в other (base+lineage) и обязан
// получить те же решения, что дал бы full. Корпус — все типы событий × варианты
// вложенных структур, бьющие по правилам каждого подпакета.

func decisionKeys(ds []PolicyDecision) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.RuleID+"|"+string(d.Severity)+"|"+d.Message+"|"+d.Action+"|"+d.MitreTechnique)
	}
	sort.Strings(out)
	return out
}

func partitionCorpus() []types.Alert {
	var out []types.Alert
	comms := []string{"bash", "nginx", "xmrig", "curl", "kubelet", "systemd"}
	files := []types.Event{}
	for _, name := range []string{
		"/etc/shadow", "/proc/1/root/etc", "/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/etc/kubernetes/admin.conf", "/run/containerd/containerd.sock", "/dev/shm/x.so",
		"/etc/ld.so.preload", "/proc/123/mem", "/home/u/.ssh/id_rsa", "/etc/sudoers.d/x", "/tmp/a",
	} {
		for _, op := range []uint8{0, 1, 2} {
			f := &types.FileEvent{Op: op, Filename: name}
			files = append(files, types.Event{File: f})
		}
	}
	nets := []types.Event{}
	for _, dport := range []uint16{22, 443, 2379, 3333, 9001, 45700, 8080} {
		for _, d := range [][16]byte{{169, 254, 169, 254}, {8, 8, 8, 8}, {10, 0, 0, 1}} {
			nets = append(nets, types.Event{Network: &types.NetworkEvent{Dport: dport, Daddr: d, Proto: 6, Family: types.AFInet}})
		}
	}
	dnss := []types.Event{
		{DNS: &types.DNSEvent{QName: "abcdefghijklmnopqrst.example.com", QType: 1}},
		{DNS: &types.DNSEvent{QName: "pool.minexmr.com", QType: 1}},
	}
	scs := []types.Event{}
	for _, nr := range []int64{101, 319, 322, 59} {
		scs = append(scs, types.Event{Syscall: &types.SyscallEvent{Nr: nr}})
	}
	variants := []types.Event{{}}
	variants = append(variants, files...)
	variants = append(variants, nets...)
	variants = append(variants, dnss...)
	variants = append(variants, scs...)
	for et := types.EventType(0); et <= 17; et++ {
		for _, v := range variants {
			for _, c := range comms {
				ev := v
				ev.Type = et
				ev.PID = 42
				copy(ev.Comm[:], c)
				if et == types.EventTLS {
					ev.TLS = &types.TLSEvent{}
				}
				out = append(out, types.Alert{RuleID: "x", Comm: c, PID: 42, Event: ev})
			}
		}
	}
	return out
}

func TestP5_NarrowPartitionIdenticalToFull(t *testing.T) {
	e, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "../../rules/rego"})
	require.NoError(t, err)
	ctx := context.Background()
	other, narrowedWithDecisions := 0, 0
	for _, a := range partitionCorpus() {
		// П5 меняет только тех, кто раньше шёл в full по типу; партиции
		// syscall/network/file/dns не тронуты (их тождество с full — не предмет П5).
		if eventTypePartition(a.Event.Type) != "other" {
			continue
		}
		got, err := e.Evaluate(ctx, a)
		require.NoError(t, err)
		want, err := e.evaluatePartition(ctx, a, "full")
		require.NoError(t, err)
		require.Equal(t, decisionKeys(want), decisionKeys(got), "type=%d partition=%s", a.Event.Type, alertPartition(&a.Event))
		if alertPartition(&a.Event) == "other" {
			other++
			if len(got) > 0 {
				narrowedWithDecisions++
			}
		}
	}
	require.GreaterOrEqual(t, other, 50, "корпус обязан содержать события, идущие в other")
	t.Logf("other: %d алертов, из них с решениями: %d", other, narrowedWithDecisions)
}

// Мутация: если выбор партиции смотрит только на тип (без проверки вложенных
// структур), событие чужого типа с File теряет решения full — корпус это ловит.
func TestP5_CorpusSeesTypeOnlyPartition(t *testing.T) {
	e, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "../../rules/rego"})
	require.NoError(t, err)
	ctx := context.Background()
	lost := 0
	for _, a := range partitionCorpus() {
		if eventTypePartition(a.Event.Type) != "other" || alertPartition(&a.Event) != "full" {
			continue
		}
		narrow, err := e.evaluatePartition(ctx, a, "other")
		require.NoError(t, err)
		full, err := e.evaluatePartition(ctx, a, "full")
		require.NoError(t, err)
		if len(decisionKeys(narrow)) != len(decisionKeys(full)) {
			lost++
		}
	}
	require.Greater(t, lost, 0, "корпус не отличает other от full на событиях с вложенной структурой")
}

func TestP5_NoCompileOfFullOnTLSAlert(t *testing.T) {
	e, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "../../rules/rego"})
	require.NoError(t, err)
	var ev types.Event
	ev.Type = types.EventTLS
	ev.TLS = &types.TLSEvent{}
	_, err = e.Evaluate(context.Background(), types.Alert{RuleID: "x", Event: ev})
	require.NoError(t, err)
	e.mu.RLock()
	defer e.mu.RUnlock()
	require.Nil(t, e.fallback.pq, "full не должен компилироваться на tls-алерте")
	require.Nil(t, e.partitioned["full"].pq)
	require.NotNil(t, e.partitioned["other"].pq)
}
