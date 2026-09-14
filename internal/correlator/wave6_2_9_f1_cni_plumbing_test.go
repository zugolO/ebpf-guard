package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.9.F.1, item 5 (№262, архив collect-6.2.9.F.1).
//
// ЧТО ВСКРЫЛ АРХИВ. Инцидент 2026-09-14T15:34:22Z, корень k3s-server, цепочка
// k3s-server → containerd → flannel → bridge, score 62,6 — рутинная настройка
// сети пода (mount/sysctl/proc_write, которые CNI-плагины делают по
// назначению). До этой правки обход containerInitTrustedRoot доходил до
// flannel и решал ИМЕНЕМ: flannel стоит в defaultTrustedComms, то есть
// `exec -a flannel /tmp/x` под тем же деревом получал ровно тот же пропуск.
// Правка переводит plumbing-хопы на ОБРАЗ (readlink /proc/<pid>/exe) и
// оставляет имя только там, где образ не разрешился, — контракт
// isImageVerifiedComm этого слоя.
//
// Резолвер отдаёт образ по pid, потому что весь смысл правки в том, что хоп
// проверяется по СВОЕМУ процессу, а не по имени в списке.
type cniImageResolver map[uint32]string

func (r cniImageResolver) ResolveExePath(pid uint32) string { return r[pid] }

func cniChain() []types.ProcessNode {
	return []types.ProcessNode{
		{PID: 9200, PPID: 1, Comm: "k3s-server"},
		{PID: 9202, PPID: 9200, Comm: "containerd"},
		{PID: 9203, PPID: 9202, Comm: "flannel"},
		{PID: 9204, PPID: 9203, Comm: "bridge"},
	}
}

// feedPodNetworkSetup подаёт пять критических алертов с листа цепочки —
// форма архива (container_escape_mount/cap_sys_admin/nsenter/proc_write,
// rootkit_proc_sysctl_write), которой хватает на score выше порога.
func feedPodNetworkSetup(t *testing.T, tr *IncidentTracker, chain []types.ProcessNode) *types.Incident {
	t.Helper()
	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, chain[len(chain)-1].PID, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Millisecond), chain[len(chain)-1].Comm)
		a.ProcessTree = chain
		tr.Add(a)
	}
	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	return &incidents[0]
}

// Положительная половина: образы плагинов на месте — дерево признаётся
// настройкой сети пода, инцидент не подтверждается атакой.
func TestWave6_2_9_F1_CNIPlumbing_VerifiedImagesStayNonAttack(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{
		9203: "/opt/cni/bin/flannel",
		9204: "/opt/cni/bin/bridge",
	})

	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	inc := feedPodNetworkSetup(t, tr, cniChain())
	assert.NotEqualf(t, types.VerdictAttack, inc.Verdict,
		"цепочка из проверенных по образу CNI-плагинов — настройка сети пода, а не атака (verdict=%v)", inc.Verdict)
}

// ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ НА СПУФ — половина, без которой правка снимала бы
// ложь и детект одинаково молча. Имя то же (flannel), образ из /tmp:
// инцидент ОБЯЗАН остаться подтверждённой атакой, и имя из
// defaultTrustedComms не имеет права его спасти.
func TestWave6_2_9_F1_CNIPlumbing_SpoofedImageStillPromotes(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{
		9203: "/tmp/flannel",
		9204: "/tmp/bridge",
	})

	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	inc := feedPodNetworkSetup(t, tr, cniChain())
	assert.Equalf(t, types.VerdictAttack, inc.Verdict,
		"`exec -a flannel /tmp/flannel` не имеет права наследовать пропуск, выданный образу плагина (verdict=%v)", inc.Verdict)
}

// Гонка readlink (образ не разрешился) НЕ меняет поведения, каким оно было до
// правки: имя всё ещё решает. Иначе каждая среда без резолвера — включая этот
// пакет тестов и любой стенд без procfs — перестала бы схлопывать
// инициализацию контейнера вовсе.
func TestWave6_2_9_F1_CNIPlumbing_UnresolvedFallsBackToName(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(cniImageResolver{})

	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	inc := feedPodNetworkSetup(t, tr, cniChain())
	assert.NotEqualf(t, types.VerdictAttack, inc.Verdict,
		"неразрешённый образ обязан падать назад на имя (flannel ∈ defaultTrustedComms), а не отзывать доверие (verdict=%v)", inc.Verdict)
}

// k3s держит свою копию плагинов в каталоге с хешем релиза. Форма пути
// точная: префикс, РОВНО один сегмент, затем /bin/<comm>.
func TestWave6_2_9_F1_CNIPlumbing_K3sDataDirImageShape(t *testing.T) {
	assert.True(t, isCNIPlumbingImage("flannel", "/var/lib/rancher/k3s/data/abc123/bin/flannel"))
	assert.True(t, isCNIPlumbingImage("bridge", "/opt/cni/bin/bridge"))
	assert.False(t, isCNIPlumbingImage("flannel", "/var/lib/rancher/k3s/data/abc123/x/bin/flannel"),
		"лишний сегмент — это не форма каталога данных k3s, а префиксный пропуск на весь каталог")
	assert.False(t, isCNIPlumbingImage("flannel", "/var/lib/rancher/k3s/data/abc123/bin/bridge"),
		"образ обязан совпадать с ИМЕНЕМ хопа, иначе пропуск выдаётся другому бинарю")
	assert.False(t, isCNIPlumbingImage("flannel", "/opt/cni/bin/flannel (deleted)"),
		"удалённый образ — сам по себе признак (T1070.004), пропуска он не получает")
	assert.False(t, isCNIPlumbingImage("xmrig", "/opt/cni/bin/xmrig"),
		"имя вне списка plumbing не становится plumbing от того, что лежит в каталоге CNI")
	assert.False(t, isCNIPlumbingImage("flannel", ""),
		"пустой образ = исключение НЕ применяется")
}
