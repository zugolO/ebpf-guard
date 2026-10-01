package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// №516 (01.10.2026). exfil_raw_socket_by_non_root и c2_raw_socket_shell обещали
// SOCK_RAW, а условие проверяло «вызван socket(2)» — любой сокет. 7890 алертов/ч
// от coredns были следствием, а не причиной. Тест держит оба конца: правило
// ловит SOCK_RAW (с флагами NONBLOCK/CLOEXEC во всех сочетаниях) и НЕ ловит
// обычные TCP/UDP сокеты, которыми coredns и любой скрипт пользуются постоянно.
func rawSocketEvent(comm string, uid uint32, sockType uint64) types.Event {
	ev := nrSyscall(41)
	ev.UID = uid
	copy(ev.Comm[:], comm)
	ev.Syscall.Args[0] = 2 // AF_INET
	ev.Syscall.Args[1] = sockType
	return ev
}

func TestWave7RawSocketRulesCheckSockType(t *testing.T) {
	const (
		sockStream   = 1
		sockDgram    = 2
		sockRaw      = 3
		sockNonblock = 0x800
		sockCloexec  = 0x80000
	)
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)

	fires := func(ev types.Event, id string) bool {
		for _, a := range re.Evaluate(ev) {
			if a.RuleID == id {
				return true
			}
		}
		return false
	}

	raw := []uint64{sockRaw, sockRaw | sockNonblock, sockRaw | sockCloexec, sockRaw | sockNonblock | sockCloexec}
	for _, typ := range raw {
		assert.True(t, fires(rawSocketEvent("python3", 1000, typ), "exfil_raw_socket_by_non_root"),
			"SOCK_RAW (type=%#x) от не-root обязан давать exfil_raw_socket_by_non_root", typ)
		assert.True(t, fires(rawSocketEvent("python3", 0, typ), "c2_raw_socket_shell"),
			"SOCK_RAW (type=%#x) из python3 обязан давать c2_raw_socket_shell", typ)
	}

	// Ровно то, что делает coredns и любой python-скрипт: потоковые и датаграммные
	// сокеты, с теми же флагами. Эти события и были 100 из 101 алерта.
	plain := []uint64{sockStream, sockDgram, sockStream | sockCloexec, sockDgram | sockNonblock | sockCloexec}
	for _, typ := range plain {
		assert.False(t, fires(rawSocketEvent("coredns", 65532, typ), "exfil_raw_socket_by_non_root"),
			"обычный сокет (type=%#x) от coredns не должен давать exfil_raw_socket_by_non_root", typ)
		assert.False(t, fires(rawSocketEvent("python3", 0, typ), "c2_raw_socket_shell"),
			"обычный сокет (type=%#x) из python3 не должен давать c2_raw_socket_shell", typ)
	}

	// Прежние предикаты не потеряны: root и ping по-прежнему не поднимают exfil-правило.
	assert.False(t, fires(rawSocketEvent("python3", 0, sockRaw), "exfil_raw_socket_by_non_root"),
		"root исключён условием uid")
	assert.False(t, fires(rawSocketEvent("ping", 1000, sockRaw), "exfil_raw_socket_by_non_root"),
		"ping исключён условием comm")
}
