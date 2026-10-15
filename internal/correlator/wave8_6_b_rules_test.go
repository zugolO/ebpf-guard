package correlator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.6, заход B, шаг 1: предикаты пяти правил из топа G0 сверены с их
// описаниями. Три исправлены предикатом (не исключением), два — нет (см. plan.md,
// «Заход B — результат»): web_sql_injection_files — описание верно, цена на
// стороне движка; web_combined_attack — описание обещает корреляцию процессов во
// времени, которую условие по одному имени файла выразить не может.

const (
	w86oWronlyCreatTrunc = 0o1101 // O_WRONLY|O_CREAT|O_TRUNC (577) — `echo x > f`
	w86oRdwr             = 0o2
	w86oRdonlyCloexec    = 0o2000000 // O_RDONLY|O_CLOEXEC — читатель
)

func w86bFile(comm, path string, op uint8, flags int32) types.Event {
	e := types.Event{Type: types.EventFileAccess, Timestamp: 1, PID: 4242,
		File: &types.FileEvent{Op: op, Flags: flags, Filename: path}}
	copy(e.Comm[:], comm)
	if op != 0 { // как у коллектора (bpf.ToTypesEvent): путь и в Filename, и в FDPath
		e.File.FDPath = path
	}
	return e
}

func w86bFires(re *RuleEngine, e types.Event, id string) bool {
	for _, a := range re.Evaluate(e) {
		if a.RuleID == id {
			return true
		}
	}
	return false
}

func w86bShipped(t *testing.T) *RuleEngine {
	t.Helper()
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	return NewRuleEngine(rules)
}

// w86bOldRule — прежний текст правила, загруженный как есть: мутация «правка не
// применена». Негативные случаи ниже на нём обязаны краснеть.
func w86bOldRule(t *testing.T, yaml string) *RuleEngine {
	t.Helper()
	p := filepath.Join(t.TempDir(), "old.yaml")
	require.NoError(t, os.WriteFile(p, []byte("rules:\n"+yaml), 0o644))
	rules, err := LoadRulesFromFile(p)
	require.NoError(t, err)
	return NewRuleEngine(rules)
}

const w86bOldPathTraversal = `
  - id: web_path_traversal_process
    name: old
    description: old
    event_type: file
    condition:
      field: filename
      op: regex
      values:
        - "(nginx|apache|httpd|node|python|php|java|tomcat|jetty|lighttpd|caddy|traefik|gunicorn|uwsgi|passenger|mongrel|webrick).*?(\\.\\.|%2e|%2f|%5c|%c0)"
        - "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%252e%252e%252f|%c0%ae).+?(nginx|apache|httpd|node|python|php|java|tomcat|jetty|lighttpd|caddy|traefik|gunicorn|uwsgi|passenger|mongrel|webrick)"
    severity: critical
    action: alert
`

const w86bOldReleaseAgent = `
  - id: container_escape_cgroup_v1_release_agent
    name: old
    description: old
    event_type: file
    condition:
      field: filename
      op: regex
      values:
        - "/sys/fs/cgroup/.*release_agent"
        - "/sys/fs/cgroup/memory/release_agent"
        - "/sys/fs/cgroup/rdma/release_agent"
    severity: critical
    action: alert
`

const w86bOldNotifyOnRelease = `
  - id: privesc_cgroup_notify_on_release
    name: old
    description: old
    event_type: file
    condition:
      field: filename
      op: regex
      values:
        - "/sys/fs/cgroup/.*/notify_on_release"
        - "/sys/fs/cgroup/.*/release_agent"
    severity: critical
    action: block
`

// web_path_traversal_process: процесс — веб-воркер И путь — обход.
func TestW86B_WebPathTraversalProcess_Predicate(t *testing.T) {
	re := w86bShipped(t)
	const id = "web_path_traversal_process"
	attack := []struct{ comm, path string }{
		{"nginx", "/var/www/html/../../etc/passwd"},
		{"apache2", "/var/www/..\\..\\windows\\win.ini"},
		{"php-fpm8.1", "/srv/app/%2e%2e%2f%2e%2e%2fetc/shadow"},
		{"python3", "/srv/app/uploads/..%2f..%2fetc/passwd"},
		{"gunicorn", "/srv/app/%252e%252e%252fetc/passwd"},
		{"node", "/srv/app/%C0%AE%C0%AE/etc/passwd"},
		{"java", "/opt/app/static/../../../etc/hosts"},
		{"python3.11", "/srv/app/%2E%2E%5Cetc"},
	}
	for _, c := range attack {
		assert.Truef(t, w86bFires(re, w86bFile(c.comm, c.path, 0, w86oRdonlyCloexec), id), "%s %s — обход веб-воркером", c.comm, c.path)
	}
	// Читатель, на котором прежний предикат срабатывал по имени сервера В ПУТИ.
	benign := []struct{ comm, path string }{
		{"python3", "/usr/lib/python3/dist-packages/apt"}, // имя сервера в пути, обхода нет
		{"nginx", "/etc/nginx/nginx.conf"},
		{"node", "/usr/lib/node_modules/npm/lib/%2f"}, // одиночный %2f — не обход
		{"bash", "/usr/lib/python3/dist-packages/../x"},
		{"grep", "/var/www/html/../../etc/passwd"}, // не веб-воркер (№144)
		{"cat", "/opt/nginx/../etc/hosts"},
		{"python3", "/usr/lib/python3.10/%c0"}, // %c0 без «%ae»
	}
	for _, c := range benign {
		assert.Falsef(t, w86bFires(re, w86bFile(c.comm, c.path, 0, w86oRdonlyCloexec), id), "%s %s — не обход веб-воркером", c.comm, c.path)
	}
	// Мутация: прежний предикат срабатывает на читателе /usr/lib/python3/….
	old := w86bOldRule(t, w86bOldPathTraversal)
	assert.True(t, w86bFires(old, w86bFile("python3", "/usr/lib/python3/dist-packages/x/../y.py", 0, 0), id),
		"прежнее условие обязано срабатывать на bash/python-читателе — иначе негативные случаи не различают")
	assert.True(t, w86bFires(old, w86bFile("cat", "/opt/nginx/../etc/hosts", 0, 0), id), "прежнее: имя сервера в пути, процесс — cat")
}

func w86bCgroupRules(t *testing.T) []struct {
	id       string
	oldYAML  string
	notifyOK bool
} {
	return []struct {
		id       string
		oldYAML  string
		notifyOK bool
	}{
		{"container_escape_cgroup_v1_release_agent", w86bOldReleaseAgent, false},
		{"privesc_cgroup_notify_on_release", w86bOldNotifyOnRelease, true},
	}
}

// cgroup-правила: изменение (write либо open с режимом записи) файла с точным
// именем release_agent / notify_on_release — в любой точке монтирования.
func TestW86B_CgroupReleaseAgentRules_Predicate(t *testing.T) {
	re := w86bShipped(t)
	for _, r := range w86bCgroupRules(t) {
		for _, path := range []string{"/sys/fs/cgroup/rdma/release_agent", "/sys/fs/cgroup/memory/release_agent", "/tmp/cgrp/release_agent"} {
			assert.Truef(t, w86bFires(re, w86bFile("tee", path, 0, w86oWronlyCreatTrunc), r.id), "%s: open O_WRONLY|O_CREAT|O_TRUNC %s", r.id, path)
			assert.Truef(t, w86bFires(re, w86bFile("python3", path, 0, w86oRdwr), r.id), "%s: open O_RDWR %s", r.id, path)
			assert.Truef(t, w86bFires(re, w86bFile("tee", path, 2, 0), r.id), "%s: write %s", r.id, path)
		}
		assert.Equalf(t, r.notifyOK, w86bFires(re, w86bFile("tee", "/sys/fs/cgroup/rdma/x/notify_on_release", 0, w86oWronlyCreatTrunc), r.id),
			"%s: notify_on_release", r.id)

		// Штатный читатель того же пути и соседние имена — молчат.
		for _, path := range []string{"/sys/fs/cgroup/rdma/release_agent", "/sys/fs/cgroup/rdma/x/notify_on_release"} {
			assert.Falsef(t, w86bFires(re, w86bFile("cat", path, 0, w86oRdonlyCloexec), r.id), "%s: чтение %s (O_RDONLY|O_CLOEXEC)", r.id, path)
			assert.Falsef(t, w86bFires(re, w86bFile("cat", path, 0, 0), r.id), "%s: чтение %s (O_RDONLY)", r.id, path)
			assert.Falsef(t, w86bFires(re, w86bFile("cat", path, 1, 0), r.id), "%s: read %s", r.id, path)
		}
		for _, path := range []string{"/sys/fs/cgroup/rdma/release_agent_notes", "/sys/fs/cgroup/memory.current",
			"/sys/fs/cgroup/rdma/not_release_agent", "/tmp/cgrp/release_agent.bak", "/var/lib/release_agent_dir/x"} {
			assert.Falsef(t, w86bFires(re, w86bFile("tee", path, 0, w86oWronlyCreatTrunc), r.id), "%s: сосед %s", r.id, path)
		}
		// Мутации (unlink/rename/truncate-хуки, op 4..7) правило без их знания не видит.
		for _, op := range []uint8{3, 4, 5, 6, 7} {
			assert.Falsef(t, w86bFires(re, w86bFile("rm", "/sys/fs/cgroup/rdma/release_agent", op, 0), r.id), "%s: op=%d", r.id, op)
		}
		// Мутация: прежнее условие срабатывает на чтении — различие негативных случаев.
		old := w86bOldRule(t, r.oldYAML)
		assert.Truef(t, w86bFires(old, w86bFile("cat", "/sys/fs/cgroup/rdma/release_agent", 0, w86oRdonlyCloexec), r.id), "%s: прежнее условие читает как атаку", r.id)
		assert.Falsef(t, w86bFires(old, w86bFile("tee", "/tmp/cgrp/release_agent", 0, w86oWronlyCreatTrunc), r.id), "%s: прежнее условие слепо к PoC в /tmp/cgrp", r.id)
	}
}

// Режим записи — flags mod 4 != 0. Регулярка по десятичной записи проверена
// против арифметики на всём диапазоне (через движок, не копией).
func TestW86B_WriteModeRegexMatchesArithmetic(t *testing.T) {
	re := w86bShipped(t)
	for _, r := range w86bCgroupRules(t) {
		for flags := int32(0); flags < 20000; flags++ {
			want := flags%4 != 0
			got := w86bFires(re, w86bFile("x", "/tmp/c/release_agent", 0, flags), r.id)
			if got != want {
				t.Fatalf("%s: flags=%d (%#o): сработало=%v, ждали %v", r.id, flags, flags, got, want)
			}
		}
		for _, flags := range []int32{0o2000000, 0o2000001, 0o2000002, 0o2000101, 0o2002001, 0o4000000 | 0o2, 1<<30 | 1, 1 << 30} {
			assert.Equalf(t, flags%4 != 0, w86bFires(re, w86bFile("x", "/tmp/c/release_agent", 0, flags), r.id), "%s: flags=%#o", r.id, flags)
		}
	}
}

// Два правила без правки: описание верно / описание не выразимо условием. Тест
// фиксирует текущее состояние, чтобы правка была решением, а не случайностью.
func TestW86B_UntouchedRulesKeepTheirPredicate(t *testing.T) {
	re := w86bShipped(t)
	// web_sql_injection_files: описание («SQL-паттерны в файловой операции») = условие.
	assert.True(t, w86bFires(re, w86bFile("php-fpm", "/tmp/x union select 1,2.log", 0, 0), "web_sql_injection_files"))
	assert.False(t, w86bFires(re, w86bFile("php-fpm", "/usr/lib/python3/dist-packages/color/monitor.py", 0, 0), "web_sql_injection_files"))
	// web_combined_attack: срабатывает на ОДНОМ имени с двумя векторами, а не на
	// «нескольких векторах одного процесса за окно» (описание).
	assert.True(t, w86bFires(re, w86bFile("nginx", "/tmp/drop table ../../x", 0, 0), "web_combined_attack"))
	assert.False(t, w86bFires(re, w86bFile("nginx", "/tmp/drop table x", 0, 0), "web_combined_attack"))
	assert.False(t, w86bFires(re, w86bFile("nginx", "/tmp/../x", 0, 0), "web_combined_attack"))
}
