package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.9.F.1, item 4 — критерий 6.2.4.6 (архив collect-6.2.9.F.1).
//
// Форма архива: инцидент 2026-09-14T15:25:15Z, корень 50-motd-news, цепочка
// 50-motd-news → 50-motd-news → dpkg, score 57, 17 алертов — штатная работа
// /etc/update-motd.d/50-motd-news (dpkg-query, /proc/version, wget). Обе
// половины hasQualifyingSignal взведены честно, поэтому инцидент промотирован
// в incident_confirmed_attack. Ось юнита снимает ярлык, НЕ трогая ни алерты,
// ни счёт, ни сам инцидент.
type unitMapResolver map[uint32]string

func (r unitMapResolver) ResolveUnit(pid uint32) string { return r[pid] }

func motdChain() []types.ProcessNode {
	return []types.ProcessNode{
		{PID: 16764, PPID: 1, Comm: "50-motd-news"},
		{PID: 16770, PPID: 16764, Comm: "50-motd-news"},
		{PID: 16780, PPID: 16770, Comm: "dpkg"},
	}
}

// feedMotdRun подаёт состав архива: пять правил с листа дерева плюс сетевой
// сигнал (wget) — ровно то, что даёт score выше порога И обе половины
// hasQualifyingSignal.
func feedMotdRun(t *testing.T, tr *IncidentTracker, ruleIDs []string) *types.Incident {
	t.Helper()
	chain := motdChain()
	now := time.Now()
	for i, id := range ruleIDs {
		a := makeAlertWithComm(id, 16780, "", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Millisecond), "dpkg")
		a.ProcessTree = chain
		tr.Add(a)
	}
	// Сетевая половина: wget под тем же деревом.
	net := makeAlertWithComm("r5", 16780, "", types.SeverityCritical,
		now.Add(5*time.Millisecond), "wget")
	net.ProcessTree = chain
	net.Event.Type = types.EventTCPConnect
	tr.Add(net)

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	return &incidents[0]
}

func withMotdUnit(t *testing.T) {
	t.Helper()
	prev, _ := unitResolver.Load().(unitResolverHolder)
	t.Cleanup(func() { SetUnitResolver(prev.r) })
	SetUnitResolver(unitMapResolver{16764: "motd-news.service"})
}

// Без списка доверенных юнитов поведение прежнее — инцидент подтверждён
// атакой. Это база, относительно которой читается вся правка: она снимает
// ярлык только там, где оператор назвал юнит.
func TestWave6_2_9_F1_TrustedUnit_EmptyListKeepsPromotion(t *testing.T) {
	withMotdUnit(t)
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	inc := feedMotdRun(t, tr, []string{"r1", "r2", "r3", "r4"})
	assert.Equal(t, types.VerdictAttack, inc.Verdict,
		"пустой список доверенных юнитов обязан оставлять поведение ДО правки")
	assert.Equal(t, "motd-news.service", inc.RootUnit,
		"юнит корня снимается всегда, даже когда ось доверия выключена — иначе вердикт нечитаем")
}

// Названный юнит: ярлык снят, инцидент ОСТАЁТСЯ (suspicious), счёт и алерты
// на месте. Объём алертов правка не двигает вовсе.
func TestWave6_2_9_F1_TrustedUnit_SoftIncidentStaysSuspicious(t *testing.T) {
	withMotdUnit(t)
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	tr.SetTrustedUnits([]string{"motd-news.service", "apt-daily*.service"})
	inc := feedMotdRun(t, tr, []string{"r1", "r2", "r3", "r4"})

	assert.NotEqualf(t, types.VerdictAttack, inc.Verdict,
		"штатная работа названного юнита не есть подтверждённая атака (verdict=%v)", inc.Verdict)
	assert.Equal(t, types.VerdictSuspicious, inc.Verdict,
		"инцидент обязан ОСТАТЬСЯ, со счётом и правилами — снимается ярлык, а не наблюдаемость")
	assert.GreaterOrEqual(t, inc.AlertCount, 5, "ни один алерт не исчезает")
	assert.Greater(t, inc.Score, 0.0, "счёт продолжает копиться")
}

// Glob: apt-daily-upgrade.service закрывается образцом apt-daily*.service, а
// посторонний юнит — нет.
func TestWave6_2_9_F1_TrustedUnit_GlobMatching(t *testing.T) {
	assert.True(t, matchUnitPattern("apt-daily*.service", "apt-daily-upgrade.service"))
	assert.True(t, matchUnitPattern("motd-news.service", "motd-news.service"))
	assert.False(t, matchUnitPattern("motd-news.service", "motd-news.service.evil"))
	assert.False(t, matchUnitPattern("apt-daily*.service", "cryptominer.service"))
	assert.False(t, matchUnitPattern("", "motd-news.service"))
	assert.False(t, matchUnitPattern("*", ""), "пустой юнит не совпадает ни с чем — ось не применяется")
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: атака ВНУТРИ доверенного юнита. Правило с тегом
// container-escape обязано промотировать инцидент несмотря на юнит — без этой
// половины правка снимала бы ложь и детект одинаково молча.
func TestWave6_2_9_F1_TrustedUnit_HardEvidenceStillPromotes(t *testing.T) {
	withMotdUnit(t)
	rules := append(scoringRules(), Rule{ID: "escape", Tags: []string{"container-escape"}})
	tr := newIncidentTracker(60*time.Second, nil, rules)
	tr.SetTrustedUnits([]string{"motd-news.service"})
	inc := feedMotdRun(t, tr, []string{"r1", "r2", "r3", "escape"})

	assert.Equal(t, types.VerdictAttack, inc.Verdict,
		"правило с тегом container-escape внутри доверенного юнита — это атака ВНУТРИ штатной задачи, ярлык остаётся")
	assert.True(t, inc.HasHardEvidence)
}

// Вторая половина твёрдой улики — исполнение из мирописуемого каталога.
// Имя юнита тут ни при чём: бинарь из /tmp не бывает частью штатной задачи.
func TestWave6_2_9_F1_TrustedUnit_ExecFromTmpStillPromotes(t *testing.T) {
	withMotdUnit(t)
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{16780: "/tmp/w626-fake-motd"})

	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	tr.SetTrustedUnits([]string{"motd-news.service"})
	inc := feedMotdRun(t, tr, []string{"r1", "r2", "r3", "r4"})

	assert.Equal(t, types.VerdictAttack, inc.Verdict,
		"процесс из /tmp под доверенным юнитом обязан промотировать — это форма положительного контроля 6.2.4.6")
}

// Юнит, которого нет в списке, доверия не получает — ось не превращается в
// «любой юнит прощён».
func TestWave6_2_9_F1_TrustedUnit_ForeignUnitStillPromotes(t *testing.T) {
	prev, _ := unitResolver.Load().(unitResolverHolder)
	t.Cleanup(func() { SetUnitResolver(prev.r) })
	SetUnitResolver(unitMapResolver{16764: "cryptominer.service"})

	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	tr.SetTrustedUnits([]string{"motd-news.service"})
	inc := feedMotdRun(t, tr, []string{"r1", "r2", "r3", "r4"})
	assert.Equal(t, types.VerdictAttack, inc.Verdict)
	assert.Equal(t, "cryptominer.service", inc.RootUnit)
}

// Разбор cgroup: форма systemd v2/v1 и отказ вместо догадки.
func TestWave6_2_9_F1_UnitFromCgroupLine(t *testing.T) {
	assert.Equal(t, "motd-news.service", unitFromCgroupLine("0::/system.slice/motd-news.service"))
	assert.Equal(t, "session-3.scope", unitFromCgroupLine("0::/user.slice/user-1000.slice/session-3.scope"))
	assert.Equal(t, "run-r7a.service", unitFromCgroupLine("1:name=systemd:/system.slice/run-r7a.service"))
	assert.Equal(t, "", unitFromCgroupLine("0::/"), "корневая cgroup юнитом не является")
	assert.Equal(t, "", unitFromCgroupLine("0::/user.slice/user-1000.slice"),
		"slice — не юнит задачи; догадываться здесь значит выдать доверие по подстроке")
	assert.Equal(t, "", unitFromCgroupLine("мусор"))
}

// РЕВИЗИЯ 14.09.2026. HasHardEvidence читается РОВНО в одной ветке
// recalculateScore, и та начинается с trustedUnitRoot(), который при пустом
// списке юнитов всегда false. Значит при выключенной оси (а она выключена по
// умолчанию и в продуктовом конфиге) readlink в isHardEvidence — чистая
// трата syscall'а на ГОРЯЧЕМ пути корреляции: по одному на каждый алерт
// каждого инцидента. Контроль держит обещание, которое даёт комментарий
// самой функции: «образ проверяется последним, readlink остаётся на редком
// пути».
func TestWave6_2_9_F1_TrustedUnit_NoReadlinkWhenAxisOff(t *testing.T) {
	withMotdUnit(t)
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	// countingExeResolver живёт в wave6_2_1_node_narrowing_test.go: счётчик
	// обращений к readlink на горячем пути — та же величина, что и здесь.
	counter := &countingExeResolver{}
	SetExePathResolver(counter)

	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	inc := feedMotdRun(t, tr, []string{"r1", "r2", "r3", "r4"})

	assert.Equal(t, types.VerdictAttack, inc.Verdict,
		"выключенная ось обязана оставлять поведение ДО правки")
	assert.Zero(t, counter.n,
		"при ПУСТОМ trusted_units образ не читается ни разу: его результат не читает никто")

	// Вторая половина — сторож «проверка вообще жива»: с непустым списком
	// тот же состав обязан дойти до readlink. Без неё ноль выше не
	// отличается от «резолвер не подключён»
	// (память positive-control-needs-result-sentinel).
	tr2 := newIncidentTracker(60*time.Second, nil, scoringRules())
	tr2.SetTrustedUnits([]string{"motd-news.service"})
	feedMotdRun(t, tr2, []string{"r1", "r2", "r3", "r4"})
	assert.Greater(t, counter.n, 0,
		"с НЕПУСТЫМ trusted_units образ обязан читаться — иначе твёрдая улика «бинарь из /tmp» не снимается вовсе")
}
