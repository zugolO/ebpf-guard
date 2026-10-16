package correlator

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func withFieldByID(on bool, f func()) {
	prev := fieldByIDEnabled
	fieldByIDEnabled = on
	defer func() { fieldByIDEnabled = prev }()
	f()
}

// network/dns/числовые события, которых нет в корпусе G3: CIDR, пороги gt/lt, пулы майнинга.
func p4ExtraCorpus() []types.Event {
	rng := rand.New(rand.NewSource(8704))
	var evs []types.Event
	comms := []string{"curl", "nc", "xmrig", "python3", "sshd", "nginx"}
	addrs := [][16]byte{{10, 1, 2, 3}, {192, 168, 1, 1}, {8, 8, 8, 8}, {169, 254, 169, 254}, {45, 9, 148, 1}, {172, 16, 0, 9}, {127, 0, 0, 1}, {1, 1, 1, 1}, {100, 64, 0, 1}}
	for i := 0; i < 3000; i++ {
		e := types.Event{Type: types.EventTCPConnect, PID: uint32(100 + rng.Intn(50)), PPID: 1, UID: uint32(rng.Intn(2) * 1000),
			Network: &types.NetworkEvent{Dport: uint16([]int{22, 80, 443, 3333, 4444, 9001, 8080, 53, 6379}[rng.Intn(9)]), Sport: uint16(1024 + rng.Intn(60000)),
				Proto: 6, Family: types.AFInet, Daddr: addrs[rng.Intn(len(addrs))], Saddr: addrs[rng.Intn(len(addrs))]}}
		if rng.Intn(5) == 0 {
			e.Network.Family = types.AFInet6
			e.Network.Daddr = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(rng.Intn(4))}
			e.Network.Saddr = [16]byte{0xfe, 0x80, 15: 1}
		}
		copy(e.Comm[:], comms[rng.Intn(len(comms))])
		evs = append(evs, e)
	}
	for i := 0; i < 300; i++ {
		e := types.Event{Type: types.EventDNS, PID: 5, DNS: &types.DNSEvent{QName: []string{"a.b.com", "xk3j2h4g5f6d7s8a9q.evil.top", "pool.minexmr.com"}[rng.Intn(3)], QType: uint16(rng.Intn(20))}}
		evs = append(evs, e)
	}
	return evs
}

// П4: те же алерты в том же порядке со значением поля по коду и по строке — на корпусе G3,
// на сетевом/DNS-корпусе и (если задан W86_DUMP) на дампе idle-часа.
func TestP4_ShippedRulesetSameAlertsByFieldID(t *testing.T) {
	// «до П4»: значение по строке и условия без предразбора; «после»: по коду + предразбор.
	var reOld, reNew *RuleEngine
	var rules []Rule
	prevPre := condPrecompile
	defer func() { condPrecompile = prevPre }()
	condPrecompile = false
	reOld, rules = loadShipped(t, true)
	condPrecompile = true
	reNew, _ = loadShipped(t, true)
	evs := append(dispatchCorpus(t, rules), p4ExtraCorpus()...)
	var a, b []string
	withFieldByID(false, func() { a = orderedAlerts(reOld, evs) })
	withFieldByID(true, func() { b = orderedAlerts(reNew, evs) })
	require.NotEmpty(t, a)
	require.Empty(t, firstDiff(a, b), "выдачи разошлись")
	t.Logf("событий %d, алертов %d", len(evs), len(a))
}
