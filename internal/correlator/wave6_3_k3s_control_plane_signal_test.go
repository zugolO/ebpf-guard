package correlator

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3, item 3 (№262/№307, item 9(б) волны 6.2.9.F.2, plan.md §6.3
// debt table). containerInitTrustedRoot (wave6_2_9_f1_cni_plumbing_test.go)
// already stops k3s-server's own namespace-setup plumbing from promoting a
// container escape it did not commit. This closes the other half of the
// same finding: k3s-server's OWN k8s_kubectl_apiserver_exec alert — control
// plane traffic to its embedded apiserver, generated continuously by design
// — otherwise sets HasNetworkSignal on every incident it belongs to,
// including ones whose root already resolved to a genuinely trusted
// container-init chain, and that one alert alone is enough to promote.

func TestIsK3sDataBinPath_MatchesK3sServerShape(t *testing.T) {
	assert.True(t, isK3sDataBinPath("/var/lib/rancher/k3s/data/abc123/bin/k3s", "k3s"))
	assert.False(t, isK3sDataBinPath("/var/lib/rancher/k3s/data/abc123/x/bin/k3s", "k3s"),
		"лишний сегмент — это не форма каталога данных k3s")
	assert.False(t, isK3sDataBinPath("/var/lib/rancher/k3s/data/abc123/bin/k3s-server", "k3s"),
		"образ обязан совпадать с ИМЕНЕМ бинаря (k3s), а не с comm (k3s-server)")
	assert.False(t, isK3sDataBinPath("/tmp/k3s", "k3s"), "чужой каталог — не образ k3s")
	assert.False(t, isK3sDataBinPath("", "k3s"), "пустой образ = исключение НЕ применяется")
}

func TestIsK3sControlPlaneNetworkSignal_Granted(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{9200: "/var/lib/rancher/k3s/data/abc123/bin/k3s"})

	before := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("granted"))
	alert := makeAlertWithComm(k8sKubectlAPIServerExecRuleID, 9200, "prod", types.SeverityWarning, time.Now(), "k3s-server")
	got := isK3sControlPlaneNetworkSignal(alert)
	after := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("granted"))

	assert.True(t, got, "verified k3s image must exempt the alert from qualifying as a network signal")
	assert.Equal(t, before+1, after, "attempt must be recorded in the granted label")
}

// Отрицательный контроль на спуф: comm тот же (k3s-server), образ — нет.
// Именно этот случай постановка называет "отрицательный контроль на спуф":
// comm подделывается тривиально (exec -a k3s-server), exe_path — нет.
func TestIsK3sControlPlaneNetworkSignal_DeniedOnSpoofedImage(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{9200: "/tmp/k3s-bypass/k3s"})

	before := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("denied"))
	alert := makeAlertWithComm(k8sKubectlAPIServerExecRuleID, 9200, "prod", types.SeverityWarning, time.Now(), "k3s-server")
	got := isK3sControlPlaneNetworkSignal(alert)
	after := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("denied"))

	assert.False(t, got, "a spoofed comm with an unverified image must NOT be exempted — the alert stays a qualifying network signal")
	assert.Equal(t, before+1, after, "attempt must be recorded in the denied label")
}

// Гонка readlink (образ не разрешился) обязана отказывать, а не проходить:
// в отличие от isImageVerifiedComm (fails open toward trust), здесь отказ
// открытый в сторону "это по-прежнему сетевой сигнал" — иначе
// короткоживущий процесс, выигравший гонку, получал бы освобождение от
// промоушена просто по факту.
func TestIsK3sControlPlaneNetworkSignal_UnresolvedDenies(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{})

	alert := makeAlertWithComm(k8sKubectlAPIServerExecRuleID, 9200, "prod", types.SeverityWarning, time.Now(), "k3s-server")
	assert.False(t, isK3sControlPlaneNetworkSignal(alert),
		"unresolved exe_path must fail open toward the alert counting as a network signal, not toward exemption")
}

// Область действия — только этот rule_id: тот же процесс, тот же образ,
// другое правило — исключение не касается его вовсе, счётчик не растёт.
func TestIsK3sControlPlaneNetworkSignal_ScopedToOneRuleID(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{9200: "/var/lib/rancher/k3s/data/abc123/bin/k3s"})

	beforeG := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("granted"))
	beforeD := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("denied"))
	alert := makeAlertWithComm("k8s_runtime_socket_access", 9200, "prod", types.SeverityWarning, time.Now(), "k3s-server")
	got := isK3sControlPlaneNetworkSignal(alert)
	afterG := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("granted"))
	afterD := testutil.ToFloat64(k3sControlPlaneNetworkSignalTotal.WithLabelValues("denied"))

	assert.False(t, got)
	assert.Equal(t, beforeG, afterG, "a different rule_id must not touch the granted counter")
	assert.Equal(t, beforeD, afterD, "a different rule_id must not touch the denied counter either — it is not an attempt")
}

// ИНЦИДЕНТНЫЙ УРОВЕНЬ — архивная форма (collect-6.2.5): корень k3s-server,
// цепочка растёт до k3s-server->containerd->flannel->bridge через
// проверенные по образу CNI-плагины (не атака, wave6_2_9_f1_cni_plumbing_test.go),
// но k3s-server ТАКЖЕ подаёт k8s_kubectl_apiserver_exec — control-plane
// коннект к своему же apiserver. До этой правки этот один network-алерт
// сам по себе промотировал инцидент в "attack".
func TestWave6_3_K3sControlPlaneSignal_VerifiedK3sDoesNotPromote(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{
		9200: "/var/lib/rancher/k3s/data/abc123/bin/k3s",
		9203: "/opt/cni/bin/flannel",
		9204: "/opt/cni/bin/bridge",
	})

	chain := cniChain()
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	inc := feedPodNetworkSetup(t, tr, chain)
	require.NotEqual(t, types.VerdictAttack, inc.Verdict, "sanity: baseline CNI setup must not already be an attack")

	netAlert := makeAlertWithComm(k8sKubectlAPIServerExecRuleID, chain[0].PID, "prod", types.SeverityWarning,
		time.Now(), chain[0].Comm)
	netAlert.Event.Type = types.EventTCPConnect
	netAlert.ProcessTree = chain
	tr.Add(netAlert)

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.NotEqualf(t, types.VerdictAttack, incidents[0].Verdict,
		"k3s-server's own verified control-plane traffic must not promote a trusted container-init chain (verdict=%v)", incidents[0].Verdict)
}

// Тот же инцидент, тот же алерт — но exe_path k3s-server не подтверждается
// (спуф или гонка). Побег из-под защёлки обязан остаться рабочим: сетевой
// сигнал по-прежнему квалифицирует, инцидент промотируется.
func TestWave6_3_K3sControlPlaneSignal_SpoofedK3sStillPromotes(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{
		9200: "/tmp/k3s-bypass/k3s",
		9203: "/opt/cni/bin/flannel",
		9204: "/opt/cni/bin/bridge",
	})

	chain := cniChain()
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	feedPodNetworkSetup(t, tr, chain)

	netAlert := makeAlertWithComm(k8sKubectlAPIServerExecRuleID, chain[0].PID, "prod", types.SeverityWarning,
		time.Now(), chain[0].Comm)
	netAlert.Event.Type = types.EventTCPConnect
	netAlert.ProcessTree = chain
	tr.Add(netAlert)

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equalf(t, types.VerdictAttack, incidents[0].Verdict,
		"a spoofed k3s-server (comm claimed, image unverified) must not inherit the exemption (verdict=%v)", incidents[0].Verdict)
}
