package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Долги 8.1 (09.10.2026, смок w81-h4): таймеры ноды man-db и apt-daily
// поднимали 3.ATTACK. Исключения — по ОБРАЗУ процесса (хост, точный путь,
// exe_path последним, отказ открытый); формы объектов и режимов — из свидетеля
// bpftrace смока (server-logs/w81-h4/smoke1).

const (
	h4Mandb     = "/usr/bin/mandb"
	h4AptHttp   = "/usr/lib/apt/methods/http"
	h4MandbExc  = "mandb-self"
	h4AptNetExc = "apt-method-net"
)

// h4MandbForms — правило, объект и режим, на которых его поднимал mandb.
var h4MandbForms = []struct {
	rule, path string
	flags      int32
}{
	{"drift_new_library_in_system_dir", "/usr/lib/man-db/libmandb-2.10.2.so", w549OCloexec},
	{"sensitive_file_read", "/etc/passwd", w549OCloexec},
	{"sigma_passwd_shadow_read", "/etc/passwd", w549OCloexec},
	{"sigma_passwd_shadow_read", "/etc/group", w549OCloexec},
	{"proc_inject_ld_preload_file", "/etc/ld.so.preload", 0},
	{"supply_chain_pkg_install_etc_write", "/etc/ld.so.preload", 0},
}

func h4Syscall(res w81CommExeResolver, pid uint32, comm, exe string, nr int64, args string, a1 uint64, uid uint32) types.Event {
	res[pid] = exe
	var c [16]byte
	copy(c[:], comm)
	return types.Event{Type: types.EventSyscall, PID: pid, UID: uid, Comm: c, ProcArgs: args,
		Syscall: &types.SyscallEvent{Nr: nr, Args: [6]uint64{0, a1}}}
}

func h4Net(res w81CommExeResolver, pid uint32, comm, exe string, dport uint16, container string) types.Event {
	res[pid] = exe
	var c [16]byte
	copy(c[:], comm)
	e := types.Event{Type: types.EventTCPConnect, PID: pid, UID: 42, Comm: c, Network: &types.NetworkEvent{Dport: dport, Proto: 6, Family: types.AFInet}}
	if container != "" {
		e.Enrichment = &types.EnrichmentInfo{ContainerID: container}
	}
	return e
}

func h4DNS(res w81CommExeResolver, pid uint32, comm, exe, qname string, rcode uint16, container string) types.Event {
	res[pid] = exe
	var c [16]byte
	copy(c[:], comm)
	e := types.Event{Type: types.EventDNS, PID: pid, UID: 42, Comm: c, DNS: &types.DNSEvent{QName: qname, RCode: rcode, QType: 1}}
	if container != "" {
		e.Enrichment = &types.EnrichmentInfo{ContainerID: container}
	}
	return e
}

// Образ /usr/bin/mandb: все семь правил подавлены и считаются.
func TestW81Mandb_Suppressed(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, f := range h4MandbForms {
		before := w81ExcCount(f.rule, h4MandbExc)
		for j, op := range []uint8{0, 1} {
			ev := w549Event(res, uint32(99000+10*i+j), "mandb", h4Mandb, f.path, op, f.flags, "")
			assert.Falsef(t, w81Fired(engine.Evaluate(ev))[f.rule], "%s на %s %s от %s", f.rule, fileOpNames[op], f.path, h4Mandb)
		}
		assert.Greaterf(t, w81ExcCount(f.rule, h4MandbExc), before, "подавление %s обязано считаться", f.rule)
	}
	// syscall-ось: exec самого образа и utimensat — ось только образ.
	for i, c := range []struct {
		rule string
		ev   func(uint32) types.Event
	}{
		{"drift_exec_from_system_bin", func(pid uint32) types.Event {
			return h4Syscall(res, pid, "mandb", h4Mandb, 59, "/usr/bin/mandb --quiet", 0, 0)
		}},
		{"evasion_timestamp_modify", func(pid uint32) types.Event { return h4Syscall(res, pid, "mandb", h4Mandb, 280, "", 0, 0) }},
	} {
		before := w81ExcCount(c.rule, h4MandbExc)
		assert.Falsef(t, w81Fired(engine.Evaluate(c.ev(uint32(99100+i))))[c.rule], "%s от mandb", c.rule)
		assert.Greaterf(t, w81ExcCount(c.rule, h4MandbExc), before, "подавление %s обязано считаться", c.rule)
	}
}

// Спуф: копия под именем mandb, пустой образ (проигранная гонка readlink),
// образ в контейнере — правила срабатывают.
func TestW81Mandb_SpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, f := range h4MandbForms {
		for j, c := range []struct{ exe, container, why string }{
			{"/var/tmp/mandb", "", "копия в /var/tmp"},
			{"/tmp/mandb", "", "копия в /tmp"},
			{"/usr/bin/cat", "", "cat с comm=mandb"},
			{"", "", "образ не разрешён (отказ открытый)"},
			{h4Mandb, w549Container, "образ mandb в контейнере"},
		} {
			ev := w549Event(res, uint32(99200+10*i+j), "mandb", c.exe, f.path, 0, f.flags, c.container)
			assert.Truef(t, w81Fired(engine.Evaluate(ev))[f.rule], "%s обязано сработать: %s", f.rule, c.why)
		}
	}
	for i, exe := range []string{"/var/tmp/mandb", "", "/usr/bin/cat"} {
		assert.Truef(t, w81Fired(engine.Evaluate(h4Syscall(res, uint32(99300+i), "mandb", exe, 59, "/usr/bin/mandb", 0, 0)))["drift_exec_from_system_bin"], "exec, образ %q", exe)
		assert.Truef(t, w81Fired(engine.Evaluate(h4Syscall(res, uint32(99310+i), "mandb", exe, 280, "", 0, 0)))["evasion_timestamp_modify"], "utimensat, образ %q", exe)
	}
}

// Образ mandb получает исключение только на своих объектах и в режиме чтения.
func TestW81Mandb_OtherObjectsAndWritesFire(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, c := range []struct {
		rule, path string
		op         uint8
		flags      int32
		why        string
	}{
		{"sensitive_file_read", "/etc/shadow", 0, w549OCloexec, "mandb читает /etc/shadow"},
		{"sigma_passwd_shadow_read", "/etc/shadow", 0, w549OCloexec, "mandb читает /etc/shadow (passwd_shadow)"},
		{"drift_new_library_in_system_dir", "/usr/lib/x86_64-linux-gnu/libevil.so", 0, w549OCloexec, "библиотека вне /usr/lib/man-db/"},
		{"drift_new_library_in_system_dir", "/usr/lib/man-db/libx.so", 0, w549ORdwr, "O_RDWR на библиотеке mandb"},
		{"proc_inject_ld_preload_file", "/etc/ld.so.preload", 0, w549ORdwr | w549OCloexec, "open O_RDWR ld.so.preload"},
		{"proc_inject_ld_preload_file", "/etc/ld.so.preload", 0, w549OWronly, "open O_WRONLY ld.so.preload"},
		{"proc_inject_ld_preload_file", "/etc/ld.so.preload", w549OpWrite, 0, "ЗАПИСЬ в ld.so.preload образом mandb"},
		{"supply_chain_pkg_install_etc_write", "/etc/ld.so.preload", w549OpWrite, 0, "запись в ld.so.preload (supply_chain)"},
		{"supply_chain_pkg_install_etc_write", "/etc/cron.d/x", 0, 0, "mandb в /etc/cron.d"},
		{"supply_chain_pkg_install_etc_write", "/etc/profile.d/x.sh", w549OpWrite, 0, "mandb пишет в /etc/profile.d"},
	} {
		ev := w549Event(res, uint32(99400+i), "mandb", h4Mandb, c.path, c.op, c.flags, "")
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[c.rule], "%s обязано сработать: %s", c.rule, c.why)
	}
}

// Два правила, у которых условие стало группой с явным legacy-набором op,
// по-прежнему не видят мутаций.
func TestW81Mandb_ConvertedRulesIgnoreMutations(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, rule := range []string{"proc_inject_ld_preload_file", "supply_chain_pkg_install_etc_write"} {
		for j, op := range w81MutationOps {
			ev := w549Event(res, uint32(99500+10*i+j), "bash", "/usr/bin/bash", "/etc/ld.so.preload", op, 0, "")
			assert.Falsef(t, w81Fired(engine.Evaluate(ev))[rule], "%s на %s", rule, fileOpNames[op])
		}
		// и прежняя семантика: open и write от чужого образа срабатывают
		for j, op := range []uint8{0, w549OpWrite} {
			ev := w549Event(res, uint32(99520+10*i+j), "bash", "/usr/bin/bash", "/etc/ld.so.preload", op, 0, "")
			assert.Truef(t, w81Fired(engine.Evaluate(ev))[rule], "%s на %s", rule, fileOpNames[op])
		}
	}
}

// Метод APT http (он же https): сетевые эвристики подавлены и считаются.
func TestW81AptMethodNet_Suppressed(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	cases := []struct {
		rule string
		ev   func(pid uint32) types.Event
	}{
		{"dns_nxdomain_flood", func(p uint32) types.Event { return h4DNS(res, p, "https", h4AptHttp, "nope.example.com", 3, "") }},
		{"mitre_dns_c2_high_frequency", func(p uint32) types.Event {
			return h4DNS(res, p, "http", h4AptHttp, "a.b.c.d.e.example.com", 0, "")
		}},
		{"netintr_syn_scan_pattern", func(p uint32) types.Event { return h4Net(res, p, "https", h4AptHttp, 443, "") }},
		{"netintr_large_upload_port", func(p uint32) types.Event { return h4Net(res, p, "https", h4AptHttp, 443, "") }},
		{"initial_package_postinstall_network", func(p uint32) types.Event { return h4Net(res, p, "http", h4AptHttp, 80, "") }},
		{"exfil_raw_socket_by_non_root", func(p uint32) types.Event {
			return h4Syscall(res, p, "http", h4AptHttp, 41, "", 3, 42)
		}},
	}
	for i, c := range cases {
		// предпосылка: без образа правило на этой форме срабатывает
		bare := engine.Evaluate(func() types.Event { e := c.ev(uint32(99600 + 10*i)); res[e.PID] = "/usr/bin/other"; return e }())
		require.Truef(t, w81Fired(bare)[c.rule], "предпосылка: %s обязано срабатывать на форме смока", c.rule)
		before := w81ExcCount(c.rule, h4AptNetExc)
		assert.Falsef(t, w81Fired(engine.Evaluate(c.ev(uint32(99601+10*i))))[c.rule], "%s от метода APT", c.rule)
		assert.Greaterf(t, w81ExcCount(c.rule, h4AptNetExc), before, "подавление %s обязано считаться", c.rule)
	}
}

// Спуф: копия метода, образ из /tmp, пустой образ, тот же образ в контейнере.
func TestW81AptMethodNet_SpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	mk := map[string]func(pid uint32, exe, container string) types.Event{
		"dns_nxdomain_flood":                  func(p uint32, exe, ct string) types.Event { return h4DNS(res, p, "http", exe, "nope.example.com", 3, ct) },
		"mitre_dns_c2_high_frequency":         func(p uint32, exe, ct string) types.Event { return h4DNS(res, p, "http", exe, "a.b.c.d.e.example.com", 0, ct) },
		"netintr_syn_scan_pattern":            func(p uint32, exe, ct string) types.Event { return h4Net(res, p, "http", exe, 443, ct) },
		"netintr_large_upload_port":           func(p uint32, exe, ct string) types.Event { return h4Net(res, p, "http", exe, 443, ct) },
		"initial_package_postinstall_network": func(p uint32, exe, ct string) types.Event { return h4Net(res, p, "http", exe, 80, ct) },
		"exfil_raw_socket_by_non_root": func(p uint32, exe, ct string) types.Event {
			e := h4Syscall(res, p, "http", exe, 41, "", 3, 42)
			if ct != "" {
				e.Enrichment = &types.EnrichmentInfo{ContainerID: ct}
			}
			return e
		},
	}
	i := 0
	for rule, f := range mk {
		for _, c := range []struct{ exe, ct, why string }{
			{"/tmp/http", "", "копия метода в /tmp"},
			{"/var/tmp/http", "", "копия в /var/tmp"},
			{"/usr/bin/curl", "", "curl с comm=http"},
			{"", "", "образ не разрешён"},
			{h4AptHttp, w549Container, "метод в контейнере"},
		} {
			i++
			assert.Truef(t, w81Fired(engine.Evaluate(f(uint32(99800+i), c.exe, c.ct)))[rule], "%s обязано сработать: %s", rule, c.why)
		}
	}
}

// Структура: имена исключений, число правил, exe_path последним и точным.
func TestW81H4_ExceptionShape(t *testing.T) {
	counts := map[string]int{}
	for _, r := range w549Rules(t) {
		for _, ex := range r.Exceptions {
			if ex.Name != h4MandbExc && ex.Name != h4AptNetExc {
				continue
			}
			counts[ex.Name]++
			require.NotNil(t, ex.ConditionGroup, r.ID)
			cs := ex.ConditionGroup.Conditions
			last := cs[len(cs)-1]
			assert.Equalf(t, "proc.exe_path", last.Field, "%s/%s: exe_path последним", r.ID, ex.Name)
			assert.Equalf(t, OpIn, last.Op, "%s/%s: точный путь", r.ID, ex.Name)
			if ex.Name == h4MandbExc {
				assert.Equal(t, []string{h4Mandb}, last.Values, r.ID)
			} else {
				assert.Equal(t, []string{h4AptHttp}, last.Values, r.ID)
			}
			var host int
			for _, c := range cs {
				if c.Field == "container.id" || c.Field == "k8s.pod" {
					host++
				}
			}
			assert.Equalf(t, 2, host, "%s/%s: хост (container.id и k8s.pod пусты)", r.ID, ex.Name)
		}
	}
	assert.Equal(t, 7, counts[h4MandbExc], "mandb-self на семи правилах")
	assert.Equal(t, 6, counts[h4AptNetExc], "apt-method-net на шести правилах")
}

// Мутация встроена: без исключений формы смока срабатывают.
func TestW81H4_MutationWithoutExceptions(t *testing.T) {
	rules := w549Rules(t)
	stripped := 0
	for i := range rules {
		keep := rules[i].Exceptions[:0]
		for _, ex := range rules[i].Exceptions {
			if ex.Name == h4MandbExc || ex.Name == h4AptNetExc {
				stripped++
				continue
			}
			keep = append(keep, ex)
		}
		rules[i].Exceptions = keep
	}
	require.Equal(t, 13, stripped)
	engine, res := w549EngineFrom(t, rules)
	for i, f := range h4MandbForms {
		ev := w549Event(res, uint32(99900+i), "mandb", h4Mandb, f.path, 0, f.flags, "")
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[f.rule], "без исключения %s обязано сработать", f.rule)
	}
	assert.True(t, w81Fired(engine.Evaluate(h4Net(res, 99950, "https", h4AptHttp, 443, "")))["netintr_syn_scan_pattern"])
}
