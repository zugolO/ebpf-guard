package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.5, находка №262 (архив collect-6.2.4): промоушен инцидента в
// "attack" считается ровно в одном месте — score >= threshold &&
// (HasUntrustedSignal || HasNetworkSignal) — а HasUntrustedSignal ставится по
// comm КАЖДОГО отдельного алерта (Add(), guard isSupervisorHop), не глядя на
// то, что корень дерева уже прошёл многохоповый обход trustedIncidentRoot
// (найденный волной 6.2.4/№255 ровно для этой формы: containerd-shim -> runc
// -> runc:[N:STAGE]). Живой лист вроде "cat" внутри этого же дерева —
// рутинный помощник инициализации namespace (container init читает файлы,
// монтирует, чистит capability-биты), а не отдельный процесс атакующего —
// но его собственный comm не входит ни в defaultTrustedComms, ни в
// containerSupervisorComms, поэтому он безусловно взводил HasUntrustedSignal
// и переводил инцидент в "attack" при достаточном score.
//
// TestIncidentTracker_TrustGate_TwoHopContainerInitStaysNonAttack (волна
// 6.2.4) проверяет ТОЛЬКО алерты, чей собственный comm уже входит в цепочку
// супервизоров/доверенных имён (runc/runc:[2:INIT]) — этот тест добавляет
// алерт с посторонним comm внутри ТОГО ЖЕ дерева, ровно форму архива 6.2.4.
func TestIncidentTracker_TrustGate_ContainerInitHelperLeafStaysNonAttack(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	// Форма архива: containerd-shim -> runc -> runc:[1:CHILD], лист "cat"
	// взвёл HasUntrustedSignal и дал ложный incident_confirmed_attack.
	chain := []types.ProcessNode{
		{PID: 6000, PPID: 1, Comm: "containerd-shim"},
		{PID: 6001, PPID: 6000, Comm: "runc"},
		{PID: 6002, PPID: 6001, Comm: "runc:[1:CHILD]"},
		{PID: 6003, PPID: 6002, Comm: "cat"},
	}
	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4"} {
		a := makeAlertWithComm(id, 6002, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "runc:[1:CHILD]")
		a.ProcessTree = chain
		tr.Add(a)
	}
	// Пятый алерт — с ЛИСТА, посторонний comm внутри того же дерева.
	leaf := makeAlertWithComm("r5", 6003, "prod", types.SeverityCritical,
		now.Add(4*time.Second), "cat")
	leaf.ProcessTree = chain
	tr.Add(leaf)

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.NotEqualf(t, types.VerdictAttack, incidents[0].Verdict,
		"лист \"cat\" внутри уже доверенного через containerInitTrustedRoot дерева "+
			"container-init не должен в одиночку подтверждать атаку (verdict=%v)",
		incidents[0].Verdict)
}

// Обратная сторона: атакующий процесс, СИДЯЩИЙ ПОД containerd-shim (реальный
// compromise контейнера), должен по-прежнему промотироваться. Это и есть
// позитивная половина 6.2.4.7, которую comment на containerInitTrustedRoot
// обещает не трогать — если сетевой сигнал корроборирует.
func TestIncidentTracker_TrustGate_AttackerUnderShimWithNetworkStillPromotes(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	chain := []types.ProcessNode{
		{PID: 7000, PPID: 1, Comm: "containerd-shim"},
		{PID: 7001, PPID: 7000, Comm: "runc"},
		{PID: 7002, PPID: 7001, Comm: "runc:[1:CHILD]"},
		{PID: 7003, PPID: 7002, Comm: "xmrig"},
	}
	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4"} {
		a := makeAlertWithComm(id, 7003, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "xmrig")
		a.ProcessTree = chain
		tr.Add(a)
	}
	netAlert := makeAlertWithComm("r5", 7003, "prod", types.SeverityCritical,
		now.Add(4*time.Second), "xmrig")
	netAlert.ProcessTree = chain
	netAlert.Event.Type = types.EventTCPConnect
	tr.Add(netAlert)

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equal(t, types.VerdictAttack, incidents[0].Verdict,
		"атакующий процесс под containerd-shim с сетевым сигналом обязан подтвердить атаку — "+
			"containerInitTrustedRoot не должен маскировать реальный compromise")
}

// Регрессия направления: cron, порождающий атакующий бинарь, — root УЖЕ
// доверен по имени (isImageVerifiedComm), но НЕ через containerInitTrustedRoot
// (cron не входит в containerSupervisorComms). Guard в Add() специально зовёт
// containerInitTrustedRoot, а не более широкий trustedIncidentRoot — этот тест
// ловит регрессию, если кто-то по ошибке заменит один на другой.
func TestIncidentTracker_TrustGate_AttackInDaemon_StillDoesNotCoalesce(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 8001, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "xmrig")
		a.ProcessTree = []types.ProcessNode{
			{PID: 8000, PPID: 1, Comm: "cron"},
			{PID: 8001, PPID: 8000, Comm: "xmrig"},
		}
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equal(t, types.VerdictAttack, incidents[0].Verdict,
		"xmrig под cron обязан подтвердить атаку — доверие к root по имени "+
			"не должно распространяться на детей через containerInitTrustedRoot")
}

// Вторая ложная форма архива collect-6.2.4 (открытый вопрос 1b волны 6.2.5,
// закрыт исходом «k3s-server — корневая плита рантайма»): корень
// `k3s-server`, цепочка k3s-server → containerd → flannel → bridge, листья
// `mount`/`loopback`. Супервизор (`containerd`) здесь на ВТОРОМ хопе, а не на
// первом, поэтому containerInitTrustedRoot в первой редакции (корень обязан
// сам быть супервизором) эту форму не покрывал и инцидент промотировался в
// attack на листе `mount`. k3s встраивает containerd, а не оборачивается им,
// — containerRootPlumbingComms называет ровно это отношение.
func TestIncidentTracker_TrustGate_K3sRootedContainerInitStaysNonAttack(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	chain := []types.ProcessNode{
		{PID: 9000, PPID: 1, Comm: "k3s-server"},
		{PID: 9001, PPID: 9000, Comm: "containerd"},
		{PID: 9002, PPID: 9001, Comm: "flannel"},
		{PID: 9003, PPID: 9002, Comm: "bridge"},
	}
	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4"} {
		a := makeAlertWithComm(id, 9002, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "flannel")
		a.ProcessTree = chain
		tr.Add(a)
	}
	// Листья архивной формы: mount/loopback — посторонние comm внутри того же
	// дерева, ровно они взводили HasUntrustedSignal.
	for i, leafComm := range []string{"mount", "loopback"} {
		leaf := makeAlertWithComm("r5", 9003, "prod", types.SeverityCritical,
			now.Add(time.Duration(4+i)*time.Second), leafComm)
		leaf.ProcessTree = chain
		tr.Add(leaf)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.NotEqualf(t, types.VerdictAttack, incidents[0].Verdict,
		"рутинная инициализация сети пода под k3s-server (mount/loopback) не должна "+
			"подтверждать атаку (verdict=%v)", incidents[0].Verdict)
}

// Антиспуф той же правки: k3s-server как корень НЕ раздаёт доверие тому, что
// под ним. Обход обязан УПЕРЕТЬСЯ в недоверенный comm и вернуть false, иначе
// «корень — плита рантайма» превратилось бы в «всё под k3s-server доверено»,
// то есть в немой обход на всей ноде.
func TestIncidentTracker_TrustGate_K3sRootedAttackerStillPromotes(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	chain := []types.ProcessNode{
		{PID: 9100, PPID: 1, Comm: "k3s-server"},
		{PID: 9101, PPID: 9100, Comm: "containerd"},
		{PID: 9102, PPID: 9101, Comm: "xmrig"},
	}
	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 9102, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "xmrig")
		a.ProcessTree = chain
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equal(t, types.VerdictAttack, incidents[0].Verdict,
		"обход останавливается на первом НЕ-супервизоре: xmrig под containerd под "+
			"k3s-server обязан подтвердить атаку")
}

// Третья половина: сам `k3s-server` как comm алерта по-прежнему взводит
// HasUntrustedSignal. containerRootPlumbingComms намеренно НЕ читается
// isSupervisorHop — процесс, назвавшийся именем ноды (`exec -a k3s-server`,
// находка №247), не должен получать право не быть недоверенным.
func TestIncidentTracker_TrustGate_K3sCommItselfStaysUntrusted(t *testing.T) {
	assert.False(t, isSupervisorHop("k3s-server"),
		"k3s-server не супервизор-хоп: имя ноды подделывается, и подделка обязана "+
			"взводить HasUntrustedSignal (см. containerRootPlumbingComms)")
	assert.True(t, isSupervisorHop("containerd"),
		"регрессия: настоящие супервизоры остаются хопами")
}
