package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.6, item 2, находка №276 (архив collect-6.2.5): фикс правки №262
// зовёт containerInitTrustedRoot(inc) в Add(), в момент прихода ОДНОГО
// алерта — а ProcessChain инцидента в этот момент ещё не дорос. Живой
// архив: инцидент создаётся с цепочкой ['k3s-server', 'mount'] (score 13,
// suspicious), через 0,7с та же incidentKey получает алерт с цепочкой
// ['k3s-server', 'containerd', 'flannel', 'bridge'] — ровно той, которую
// правка №262 писалась покрывать — но решение о "mount" уже принято на
// обрубке дерева и не пересматривается: старая (латчащая bool) реализация
// промотирует инцидент в "attack".
//
// Этот тест воспроизводит ровно эту гонку: первый алерт создаёт инцидент
// на коротком дереве, из-за которого containerInitTrustedRoot(inc) на
// момент его прихода возвращает false и "mount" копится как недоверенный
// comm; последующие алерты донашивают цепочку до формы, которую
// containerInitTrustedRoot принимает (containerd -> flannel, k3s-server —
// containerRootPlumbingComms). Инцидент обязан остаться НЕ "attack":
// hasQualifyingUntrustedComm обязан пересчитываться по ТЕКУЩЕЙ цепочке на
// каждый проход recalculateScore, а не один раз при первом алерте.
func TestIncidentTracker_UntrustedComm_ReevaluatedAsChainGrows(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	root := types.ProcessNode{PID: 9200, PPID: 1, Comm: "k3s-server"}
	shortChain := []types.ProcessNode{
		root,
		{PID: 9201, PPID: 9200, Comm: "mount"},
	}
	fullChain := []types.ProcessNode{
		root,
		{PID: 9202, PPID: 9200, Comm: "containerd"},
		{PID: 9203, PPID: 9202, Comm: "flannel"},
		{PID: 9204, PPID: 9203, Comm: "bridge"},
	}

	now := time.Now()

	// r1 arrives on the short, not-yet-resolved chain: this is the alert
	// that used to latch HasUntrustedSignal permanently.
	first := makeAlertWithComm("r1", 9201, "prod", types.SeverityCritical, now, "mount")
	first.ProcessTree = shortChain
	tr.Add(first)

	before := tr.GetAll("", "", 0)
	require.Len(t, before, 1)
	assert.Contains(t, before[0].UntrustedComms, "mount",
		"the short-chain alert must still be recorded as an untrusted comm")
	assert.NotEqual(t, types.VerdictAttack, before[0].Verdict,
		"one low-score alert must not promote on its own")

	// 0.7s later (archive timing) the chain grows to the form
	// containerInitTrustedRoot resolves to a trusted actor (flannel, past the
	// containerd supervisor hop), and enough distinct rules fire to cross the
	// attack score threshold.
	start := now.Add(700 * time.Millisecond)
	for i, id := range []string{"r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 9204, "prod", types.SeverityCritical,
			start.Add(time.Duration(i)*time.Millisecond), "bridge")
		a.ProcessTree = fullChain
		tr.Add(a)
	}

	after := tr.GetAll("", "", 0)
	require.Len(t, after, 1, "the growing chain must not fork a new incident")
	assert.Contains(t, after[0].UntrustedComms, "bridge",
		"the leaf comm under the resolved chain is still recorded")
	assert.NotEqualf(t, types.VerdictAttack, after[0].Verdict,
		"routine k3s-server -> containerd -> flannel namespace-setup traffic must not "+
			"confirm attack just because an earlier alert saw a shorter chain (verdict=%v)",
		after[0].Verdict)
}

// Антиспуф той же правки: если после того, как цепочка выросла, в дереве
// появляется ДЕЙСТВИТЕЛЬНО чужой процесс (не лист инициализации namespace),
// он обязан по-прежнему промотировать инцидент — снятие защёлки не должно
// превратиться в немой обход через "один раз увидели supervisor — и больше
// не проверяем".
func TestIncidentTracker_UntrustedComm_RealAttackerAfterChainGrowsStillPromotes(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	root := types.ProcessNode{PID: 9300, PPID: 1, Comm: "k3s-server"}
	chain := []types.ProcessNode{
		root,
		{PID: 9301, PPID: 9300, Comm: "containerd"},
		{PID: 9302, PPID: 9301, Comm: "xmrig"},
	}

	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 9302, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Millisecond), "xmrig")
		a.ProcessTree = chain
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equal(t, types.VerdictAttack, incidents[0].Verdict,
		"walk ends on an untrusted comm (xmrig, not flannel/a trusted actor) — must still promote")
}
