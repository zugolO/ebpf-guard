package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.6, item 6 (находка №282): остаток гейта сужается по разбивке
// прогона 6.2.5. Четыре file-правила получили исключения по идиоме
// node-host-daemon (cgroup + pod + exe_path, образ последним), на РОВНО тех
// парах (comm, путь), которые архив 6.2.5 назвал поимённо
// (server-logs/collect-6.2.5/controls/artifacts/alerts-window-end.json).
//
// Каждое сужение проверяется ОБЕИМИ половинами, как требует правило В
// «Перенос в 6.1…6.4»: фон ноды замолкает И атака, ради которой правило
// существует, по-прежнему поднимает алерт. Негативные половины здесь — это
// цена по детекту, и их три вида:
//
//   1) тот же comm, тот же хостовой контекст, но ДРУГОЙ путь — примитив
//      разведки/побега, ради которого правило и написано;
//   2) тот же comm и тот же путь, но процесс В КОНТЕЙНЕРЕ — слой 1 отвечает
//      «это не демон ноды»;
//   3) тот же comm и тот же путь на хосте, но образ подделан (exec -a из
//      /tmp) — слой 2, единственная неподделываемая ось
//      ([[exe-path-is-the-antispoof-axis]]).
//
// Два info-ярусных кандидата item 6 — recon_security_tools_enum (3) и
// recon_process_enum (1) — здесь НЕ трогаются и тестов не имеют: их условие
// само есть список comm, сужать их по оси comm нечем, а измеренного источника
// для них не существует (стор слеп к info-ярусу, см. открытый вопрос волны).

const (
	w626i6PIDsysinfo uint32 = 96001 // landscape-sysinfo, настоящий
	w626i6PIDlogind  uint32 = 96002 // systemd-logind, настоящий
	w626i6PIDsshd    uint32 = 96003 // sshd, настоящий
	w626i6PIDk3s     uint32 = 96004 // k3s-server, настоящий
	w626i6PIDspoof   uint32 = 96099 // тот же comm, образ из /tmp
)

type w626i6Resolver struct{}

func (w626i6Resolver) ResolveExePath(pid uint32) string {
	switch pid {
	case w626i6PIDsysinfo:
		// comm усечён ядром до "landscape-sysin", а образ — интерпретатор.
		return "/usr/bin/python3"
	case w626i6PIDlogind:
		return "/usr/lib/systemd/systemd-logind"
	case w626i6PIDsshd:
		return "/usr/sbin/sshd"
	case w626i6PIDk3s:
		return "/usr/local/bin/k3s"
	case w626i6PIDspoof:
		return "/tmp/payload"
	}
	return ""
}

func w626i6Rule(t *testing.T, file, id string) *RuleEngine {
	t.Helper()
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(w626i6Resolver{})
	t.Cleanup(func() { SetExePathResolver(prev.r) })

	rules, err := LoadRulesFromFile(file)
	require.NoError(t, err)
	for i := range rules {
		if rules[i].ID == id {
			return NewRuleEngine([]Rule{rules[i]})
		}
	}
	require.FailNowf(t, "rule not found", "%s in %s", id, file)
	return nil
}

// w626i6File — file-событие от имени конкретного pid (то есть конкретного
// образа), с необязательной идентичностью из cgroup.
func w626i6File(pid uint32, comm, path string, id *types.EnrichmentInfo) types.Event {
	e := types.Event{Type: types.EventFileAccess, PID: pid, File: &types.FileEvent{Op: 0}}
	copy(e.Comm[:], comm)
	copy(e.File.Filename[:], path)
	e.Enrichment = id
	return e
}

// w626i6InPod — идентичность, которую вешает обогатитель на процесс в поде.
// На хосте она пуста и подделать её изнутри пода нельзя.
func w626i6InPod() *types.EnrichmentInfo {
	return &types.EnrichmentInfo{
		Namespace:     "default",
		PodName:       "attacker",
		ContainerID:   "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678901234567890123456789012",
		RuntimeSource: "k8s",
	}
}

// ---------------------------------------------------------------------------
// sigma_cpu_info_access — 1 алерт/окно в 6.2.5, источник landscape-sysinfo
// на /proc/meminfo (прежнее исключение k3s-server-node-capacity-poll в этом
// прогоне не сработало — источник сменился).
// ---------------------------------------------------------------------------

func TestWave6_2_6Item6_SigmaCPUInfoAccess(t *testing.T) {
	e := w626i6Rule(t, "../../rules/sigma-linux.yaml", "sigma_cpu_info_access")

	assert.Empty(t, e.Evaluate(w626i6File(w626i6PIDsysinfo, "landscape-sysin", "/proc/meminfo", nil)),
		"генератор MOTD, читающий /proc/meminfo на хосте, не должен давать алерт")

	// (1) другой путь тем же демоном: /proc/version и /proc/sys/kernel/* —
	// отпечаток ядра для подбора эксплойта, исключение их не покрывает.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDsysinfo, "landscape-sysin", "/proc/version", nil)),
		"тот же демон на /proc/version обязан алертить")
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDsysinfo, "landscape-sysin", "/proc/sys/kernel/osrelease", nil)),
		"тот же демон на /proc/sys/kernel/osrelease обязан алертить")
	// /proc/cpuinfo намеренно НЕ внесён в исключение: замер его не показывал.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDsysinfo, "landscape-sysin", "/proc/cpuinfo", nil)),
		"путь, которого замер не показывал, обязан остаться под правилом")

	// (2) то же имя и путь, но из пода.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDsysinfo, "landscape-sysin", "/proc/meminfo", w626i6InPod())),
		"процесс в поде с тем же comm обязан алертить")

	// (3) то же имя и путь на хосте, но образ из /tmp.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDspoof, "landscape-sysin", "/proc/meminfo", nil)),
		"подделка имени демона из /tmp обязана алертить")
}

// ---------------------------------------------------------------------------
// mitre_sandbox_detect_proc_read — 1 алерт/окно в 6.2.5. Два наблюдённых
// источника: landscape-sysinfo на /proc/uptime и systemd-logind на
// /proc/1/cgroup.
// ---------------------------------------------------------------------------

func TestWave6_2_6Item6_MitreSandboxDetectProcRead(t *testing.T) {
	e := w626i6Rule(t, "../../rules/mitre-additional.yaml", "mitre_sandbox_detect_proc_read")

	assert.Empty(t, e.Evaluate(w626i6File(w626i6PIDsysinfo, "landscape-sysin", "/proc/uptime", nil)),
		"генератор MOTD на /proc/uptime не должен давать алерт")
	assert.Empty(t, e.Evaluate(w626i6File(w626i6PIDlogind, "systemd-logind", "/proc/1/cgroup", nil)),
		"systemd-logind, разрешающий cgroup лидера сессии, не должен давать алерт")

	// (1) настоящие примитивы разведки хоста остаются под правилом у обоих.
	for _, path := range []string{"/proc/1/environ", "/proc/1/status"} {
		assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDsysinfo, "landscape-sysin", path, nil)),
			"landscape-sysin на %s обязан алертить", path)
		assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDlogind, "systemd-logind", path, nil)),
			"systemd-logind на %s обязан алертить", path)
	}

	// (2) из пода.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDlogind, "systemd-logind", "/proc/1/cgroup", w626i6InPod())),
		"процесс в поде с comm=systemd-logind обязан алертить")

	// (3) подделанный образ.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDspoof, "systemd-logind", "/proc/1/cgroup", nil)),
		"подделка systemd-logind из /tmp обязана алертить")
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDspoof, "landscape-sysin", "/proc/uptime", nil)),
		"подделка landscape-sysin из /tmp обязана алертить")
}

// ---------------------------------------------------------------------------
// container_escape_init_proc — 1 алерт/окно в 6.2.5. Четыре наблюдённых
// источника фона ноды.
// ---------------------------------------------------------------------------

func TestWave6_2_6Item6_ContainerEscapeInitProc(t *testing.T) {
	e := w626i6Rule(t, "../../rules/container-escape.yaml", "container_escape_init_proc")

	type src struct {
		pid  uint32
		comm string
		path string
	}
	silenced := []src{
		{w626i6PIDsysinfo, "landscape-sysin", "/proc/1/cmdline"},
		{w626i6PIDlogind, "systemd-logind", "/proc/1/cgroup"},
		{w626i6PIDsshd, "sshd", "/proc/1/limits"},
		{w626i6PIDk3s, "k3s-server", "/proc/1/net/dev"},
	}

	for _, s := range silenced {
		assert.Empty(t, e.Evaluate(w626i6File(s.pid, s.comm, s.path, nil)),
			"фон ноды %s на %s не должен давать алерт", s.comm, s.path)

		// (1) примитивы побега остаются под правилом у того же демона.
		for _, esc := range []string{"/proc/1/environ", "/proc/1/mem", "/proc/1/root/etc/shadow", "/proc/self/root/proc/1/cgroup"} {
			assert.NotEmpty(t, e.Evaluate(w626i6File(s.pid, s.comm, esc, nil)),
				"%s на %s обязан алертить", s.comm, esc)
		}

		// (2) тот же comm и путь, но из пода.
		assert.NotEmpty(t, e.Evaluate(w626i6File(s.pid, s.comm, s.path, w626i6InPod())),
			"%s в поде обязан алертить", s.comm)

		// (3) тот же comm и путь на хосте, но образ из /tmp.
		assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDspoof, s.comm, s.path, nil)),
			"подделка %s из /tmp обязана алертить", s.comm)
	}
}

// ---------------------------------------------------------------------------
// drift_new_file_dir_sensitive — 1 алерт/окно в 6.2.5. Единственный источник
// вне дерева измерителя: sshd на /root/.ssh/authorized_keys.
// ---------------------------------------------------------------------------

func TestWave6_2_6Item6_DriftNewFileDirSensitive(t *testing.T) {
	e := w626i6Rule(t, "../../rules/drift-rules.yaml", "drift_new_file_dir_sensitive")

	assert.Empty(t, e.Evaluate(w626i6File(w626i6PIDsshd, "sshd", "/root/.ssh/authorized_keys", nil)),
		"sshd, читающий authorized_keys при аутентификации, не должен давать алерт")

	// (1) любой другой путь под /root/ и каталоги персистенции — у того же sshd.
	for _, path := range []string{"/root/.bashrc", "/root/.ssh/id_rsa", "/etc/cron.d/backdoor", "/var/spool/cron/root", "/etc/systemd/system/evil.service"} {
		assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDsshd, "sshd", path, nil)),
			"sshd на %s обязан алертить", path)
	}

	// (2) из пода.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDsshd, "sshd", "/root/.ssh/authorized_keys", w626i6InPod())),
		"процесс в поде с comm=sshd обязан алертить")

	// (3) подделанный образ.
	assert.NotEmpty(t, e.Evaluate(w626i6File(w626i6PIDspoof, "sshd", "/root/.ssh/authorized_keys", nil)),
		"подделка sshd из /tmp обязана алертить")
}

// Регрессия постановки: два правила, которые item 6 НЕ трогает, потому что их
// дубль на одном событии есть позитивная половина живого детекта.
func TestWave6_2_6Item6_UntouchedPositivePair(t *testing.T) {
	for _, c := range []struct{ file, id string }{
		{"../../rules/credential-access.yaml", "sensitive_file_read"},
		{"../../rules/sigma-linux.yaml", "sigma_passwd_shadow_read"},
	} {
		rules, err := LoadRulesFromFile(c.file)
		require.NoErrorf(t, err, "load %s", c.file)
		var found bool
		for i := range rules {
			if rules[i].ID != c.id {
				continue
			}
			found = true
			for _, exc := range rules[i].Exceptions {
				assert.NotEqual(t, "node-host-daemon", exc.Name,
					"%s не должен получать сужение фона ноды: это доказательство детекта", c.id)
			}
		}
		assert.True(t, found, "правило %s не найдено в %s", c.id, c.file)
	}
}
