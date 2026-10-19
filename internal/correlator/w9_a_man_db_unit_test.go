package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 9, заход A, В5 (решение владельца 18.10.2026): запрет 5.9.9.F.3 на реестр акторов
// не снимается — правила, давшие алерты на детях man-db.service (ночь 8.7, 08:30:58),
// сужены исключением по ЮНИТУ (proc.systemd_unit, cgroup_id из ядра). Каждая сторона
// исключения (подавляет / не подавляет) доказывается отдельно.

const (
	w9CgManDB = 7001 // man-db.service
	w9CgCron  = 7002 // cron.service
	w9CgUser  = 7003 // user.slice — резолвер system.slice его не знает

	w9Exc    = "man-db-unit-child"
	w9OpOpen = 0
)

func w9Units() w81UnitResolver {
	return w81UnitResolver{w9CgManDB: "man-db.service", w9CgCron: "cron.service"}
}

func w9Syscall(res w81CommExeResolver, pid uint32, comm string, nr int64, cg uint64, container string) types.Event {
	e := h4Syscall(res, pid, comm, "", nr, "", 0, 0)
	e.CgroupID = cg
	if container != "" {
		e.Enrichment = &types.EnrichmentInfo{ContainerID: container}
	}
	return e
}

const (
	nrPtrace  = 101
	nrMount   = 165
	nrUmount2 = 166
	nrSetns   = 308
	nrSeccomp = 317
	nrBpf     = 321
	nrUnshare = 272
)

// Подавляется: песочница юнита — mount/umount2/unshare/seccomp от предэкзековых детей.
func TestW9A_ManDBSandboxChildrenSuppressed(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w9Units())
	pid := uint32(98000)
	for _, comm := range []string{"(mandb)", "(find)", "(install)"} {
		for _, c := range []struct {
			rule string
			nr   int64
		}{
			{"drift_dangerous_syscall", nrMount},
			{"drift_dangerous_syscall", nrUmount2},
			{"drift_dangerous_syscall", nrUnshare},
			{"sigma_seccomp_filter_install", nrSeccomp},
		} {
			pid++
			before := w81ExcCount(c.rule, w9Exc)
			fired := w81Fired(engine.Evaluate(w9Syscall(res, pid, comm, c.nr, w9CgManDB, "")))
			assert.Falsef(t, fired[c.rule], "%s от %s в man-db.service (nr %d)", c.rule, comm, c.nr)
			assert.Greaterf(t, w81ExcCount(c.rule, w9Exc), before, "%s: подавление обязано считаться (%s)", c.rule, comm)
		}
	}
}

// Не подавляется: спуф имени вне юнита, контейнер, юнит не определён, чужой comm, другие примитивы.
func TestW9A_ManDBSandboxSpoofAndOtherPrimitivesFire(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w9Units())
	pid := uint32(98100)
	type c struct {
		rule, why, comm string
		nr              int64
		cg              uint64
		container       string
	}
	for _, x := range []c{
		{"drift_dangerous_syscall", "то же имя в cron.service", "(mandb)", nrMount, w9CgCron, ""},
		{"drift_dangerous_syscall", "то же имя в user.slice", "(mandb)", nrMount, w9CgUser, ""},
		{"drift_dangerous_syscall", "юнит не определён (cgroup 0)", "(mandb)", nrMount, 0, ""},
		{"drift_dangerous_syscall", "контейнер", "(mandb)", nrMount, w9CgManDB, "aa957db9bd4d"},
		{"drift_dangerous_syscall", "чужой comm в man-db.service", "python3", nrMount, w9CgManDB, ""},
		{"drift_dangerous_syscall", "ptrace из того же юнита и comm", "(mandb)", nrPtrace, w9CgManDB, ""},
		{"drift_dangerous_syscall", "setns из того же юнита и comm", "(mandb)", nrSetns, w9CgManDB, ""},
		{"drift_dangerous_syscall", "bpf из того же юнита и comm", "(mandb)", nrBpf, w9CgManDB, ""},
		{"sigma_seccomp_filter_install", "то же имя в cron.service", "(find)", nrSeccomp, w9CgCron, ""},
		{"sigma_seccomp_filter_install", "user.slice", "(find)", nrSeccomp, w9CgUser, ""},
		{"sigma_seccomp_filter_install", "контейнер", "(find)", nrSeccomp, w9CgManDB, "aa957db9bd4d"},
		{"sigma_seccomp_filter_install", "чужой comm в man-db.service", "bash", nrSeccomp, w9CgManDB, ""},
	} {
		pid++
		fired := w81Fired(engine.Evaluate(w9Syscall(res, pid, x.comm, x.nr, x.cg, x.container)))
		assert.Truef(t, fired[x.rule], "%s обязано сработать: %s", x.rule, x.why)
	}
}

func w9File(res w81CommExeResolver, pid uint32, comm, path string, op uint8, cg uint64, container string) types.Event {
	return h5File(res, pid, comm, "", path, op, 0, cg, container)
}

// sensitive_file_read: /etc/passwd от детей юнита подавляется; /etc/shadow, чужой юнит, запись — нет.
func TestW9A_ManDBSensitiveFileRead(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w9Units())
	const rule = "sensitive_file_read"
	pid := uint32(98200)
	for _, comm := range []string{"(mandb)", "(find)", "(install)", "install"} {
		pid++
		before := w81ExcCount(rule, w9Exc)
		fired := w81Fired(engine.Evaluate(w9File(res, pid, comm, "/etc/passwd", w9OpOpen, w9CgManDB, "")))
		assert.Falsef(t, fired[rule], "%s читает /etc/passwd в man-db.service", comm)
		assert.Greater(t, w81ExcCount(rule, w9Exc), before)
	}
	for _, x := range []struct {
		why, comm, path string
		cg              uint64
		container       string
	}{
		{"/etc/shadow из того же юнита и comm", "(mandb)", "/etc/shadow", w9CgManDB, ""},
		{"/etc/gshadow из того же юнита", "install", "/etc/gshadow", w9CgManDB, ""},
		{"то же имя в cron.service", "(mandb)", "/etc/passwd", w9CgCron, ""},
		{"user.slice", "install", "/etc/passwd", w9CgUser, ""},
		{"юнит не определён", "install", "/etc/passwd", 0, ""},
		{"контейнер", "install", "/etc/passwd", w9CgManDB, "aa957db9bd4d"},
		{"чужой comm в man-db.service", "curl", "/etc/passwd", w9CgManDB, ""},
	} {
		pid++
		fired := w81Fired(engine.Evaluate(w9File(res, pid, x.comm, x.path, w9OpOpen, x.cg, x.container)))
		assert.Truef(t, fired[rule], "%s обязано сработать: %s", rule, x.why)
	}
}

// anomaly_detection (синтетическое правило, исключения через EvaluateNamedExceptions) и
// drift_exec_from_system_bin на find/install/mandb из man-db.service.
func TestW9A_ManDBAnomalyAndExecDrift(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w9Units())
	pid := uint32(98300)
	// синтетическое правило не видит comm: ось только юнит, подавляется любая аномалия внутри man-db.service
	for _, comm := range []string{"mandb", "find", "install", "(mandb)", "(find)", "(install)", "curl"} {
		pid++
		ev := w9Syscall(res, pid, comm, nrMount, w9CgManDB, "")
		assert.Truef(t, engine.EvaluateNamedExceptions("anomaly_detection", ev), "anomaly_detection от %s в man-db.service подавляется (ось — юнит)", comm)
		for _, bad := range []struct {
			why string
			cg  uint64
			ctr string
		}{{"cron.service", w9CgCron, ""}, {"user.slice", w9CgUser, ""}, {"юнит не определён", 0, ""}, {"контейнер", w9CgManDB, "aa957db9bd4d"}} {
			pid++
			ev := w9Syscall(res, pid, comm, nrMount, bad.cg, bad.ctr)
			assert.Falsef(t, engine.EvaluateNamedExceptions("anomaly_detection", ev), "anomaly_detection от %s: %s не подавляется", comm, bad.why)
		}
	}

	// drift_exec_from_system_bin: правило — execve системного образа; сюда те же find/install.
	rules := w549Rules(t)
	var exec Rule
	for _, r := range rules {
		if r.ID == "drift_exec_from_system_bin" {
			exec = r
		}
	}
	assert.NotEmpty(t, exec.ID)
	have := false
	for _, ex := range exec.Exceptions {
		if ex.Name == "man-db-unit-exec" {
			have = true
		}
	}
	assert.True(t, have, "у drift_exec_from_system_bin нет исключения man-db-unit-exec")
	pid++
	ev := w9Syscall(res, pid, "install", 59, w9CgManDB, "")
	assert.True(t, engine.EvaluateNamedExceptions("drift_exec_from_system_bin", ev), "install в man-db.service подавляется")
	pid++
	ev = w9Syscall(res, pid, "install", 59, w9CgCron, "")
	assert.False(t, engine.EvaluateNamedExceptions("drift_exec_from_system_bin", ev), "install в cron.service не подавляется")
}
