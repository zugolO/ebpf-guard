package correlator

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.2.2, point 4 of "Что делает волна 6.2.2" — the three rules that
// matched wider than their own name. №231 (c2_periodic_beacon_pattern) and
// №234 (sigma_log_deletion) have their own tests; this file holds the
// remaining two: beacon_fixed_interval (open question 4 — same defect as
// №231, left untouched at the time) and sigma_iptables_flush.
//
// Each is asserted on BOTH halves, as rule В of "Перенос в 6.1…6.4" requires:
// the background the rule must not name, and the thing the rule exists for.

func loadRule(t *testing.T, file, id string) Rule {
	t.Helper()
	rules, err := LoadRulesFromFile(file)
	require.NoError(t, err)
	for i := range rules {
		if rules[i].ID == id {
			return rules[i]
		}
	}
	t.Fatalf("rule %s not found in %s", id, file)
	return Rule{}
}

func TestWave6_2_2_BeaconFixedInterval_RequiresPeriodicity(t *testing.T) {
	globalBeaconInterval = NewBeaconIntervalTracker()
	t.Cleanup(func() { globalBeaconInterval = NewBeaconIntervalTracker() })
	engine := NewRuleEngine([]Rule{loadRule(t, "../../rules/command-and-control.yaml", "beacon_fixed_interval")})

	connect := func(comm string, dport uint16, daddr string, at time.Time) types.Event {
		e := types.Event{
			Type: types.EventTCPConnect, PID: 7311, Timestamp: uint64(at.UnixNano()),
			Network: &types.NetworkEvent{Dport: dport, Family: types.AFInet},
		}
		copy(e.Comm[:], comm)
		copy(e.Network.Daddr[:], net.ParseIP(daddr).To4())
		globalBeaconInterval.Record(e.PID, e.Network.Daddr, e.Network.Dport, eventTime(e))
		return e
	}

	t.Run("a single connection is not a fixed-interval beacon", func(t *testing.T) {
		// Before wave 6.2.2 this raised a warning on the first connection —
		// the rule promised "repeated ... at fixed intervals" and checked
		// neither, leaning entirely on the exception list to stay quiet.
		e := connect("some-agent", 9001, "198.51.100.7", time.Now())
		assert.Empty(t, engine.Evaluate(e))
	})

	t.Run("a regular cadence to one destination still alerts", func(t *testing.T) {
		globalBeaconInterval = NewBeaconIntervalTracker()
		base := time.Now()
		var last []types.Alert
		for i := 0; i < 4; i++ {
			e := connect("some-agent", 9001, "198.51.100.7", base.Add(time.Duration(i)*20*time.Second))
			last = engine.Evaluate(e)
		}
		assert.NotEmpty(t, last, "the canonical fixed-interval beacon must still be caught")
	})

	t.Run("repeated but irregular connections stay quiet", func(t *testing.T) {
		globalBeaconInterval = NewBeaconIntervalTracker()
		base := time.Now()
		var last []types.Alert
		for _, gap := range []time.Duration{0, 3 * time.Second, 51 * time.Second, 4 * time.Second} {
			base = base.Add(gap)
			last = engine.Evaluate(connect("chatty-app", 9001, "198.51.100.7", base))
		}
		assert.Empty(t, last, "irregular repetition is traffic, not a beacon")
	})
}

func TestWave6_2_2_SigmaIptablesFlush_StaysInsideOneCommand(t *testing.T) {
	engine := NewRuleEngine([]Rule{loadRule(t, "../../rules/sigma-linux.yaml", "sigma_iptables_flush")})

	exec := func(args string) types.Event {
		e := types.Event{
			Type: types.EventSyscall, PID: 4242, ProcArgs: args,
			Syscall: &types.SyscallEvent{Nr: 59},
		}
		copy(e.Comm[:], "sh")
		return e
	}

	t.Run("a flag from another command does not count as an iptables flush", func(t *testing.T) {
		assert.Empty(t, engine.Evaluate(exec(`sh -c grep iptables /etc/rc.local; tar -F list.txt`)),
			"the name of the rule is 'iptables flush', not 'the word iptables somewhere on the line'")
		assert.Empty(t, engine.Evaluate(exec(`cat /etc/iptables/rules.v4 | grep -F DROP`)))
	})

	t.Run("real flushes and chain deletes still alert", func(t *testing.T) {
		for _, args := range []string{
			`iptables -F`,
			`iptables -t nat -F`,
			`/sbin/ip6tables --flush`,
			`iptables -w 5 -X CHAIN`,
			`ufw disable`,
			`systemctl stop firewalld`,
		} {
			assert.NotEmptyf(t, engine.Evaluate(exec(args)), "must alert on %q", args)
		}
	})
}
