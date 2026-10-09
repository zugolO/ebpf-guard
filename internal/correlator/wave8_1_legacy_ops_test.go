package correlator

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.1, №543. Хуки item 7 (unlink/rename/truncate/rmdir, op 4..7) молча
// расширили на мутации каждое файловое правило, не называвшее op. Ночь H
// (07.10.2026 06:41–06:46, unattended-upgrades ставил ядро):
// container_escape_module_access — условие только префикс /lib/modules/ —
// дал дедуп 169 655 и срез лимитера 67 468 на rename/unlink/rmdir dpkg.
// Пара A/B item 7 этого не видела: в её окнах dpkg не запускался (№544).
//
// Починка — Rule.legacyOpsOnly: правило без op ни в одной ветке (условие,
// condition_group, exceptions) видит только open/read/write/chmod.
//
// Мутационная проверка (г) выполнена вручную 07.10.2026: ранний выход в
// matchesTypedCached закомментирован → TestWave8_1_ModuleAccessIgnoresMutations
// краснеет на всех четырёх операциях («обязано молчать на unlink/rename/
// truncate/rmdir»), возвращён → зелёный. Та же мутация встроена ниже
// автоматически (TestWave8_1_LegacyOpsGuardCanFail), чтобы гард не мог
// тихо стать вакуумным.

var w81MutationOps = []uint8{w81OpUnlink, w81OpRename, w81OpTruncate, w81OpRmdir}

// w81MutationVisibleRules — файловые правила поставляемого набора, которые
// называют op и потому видят мутации. Новое правило, назвавшее op, обязано
// попасть сюда решением автора; правило без op сюда не попадёт никогда.
var w81MutationVisibleRules = strings.Fields(`
collection_direct_db_file_access collection_local_mail_spool_access container_escape_module_access container_escape_proc_write
cred_aws_credentials_read cred_bash_history_read cred_browser_store_read cred_docker_auth_read
cred_gcp_service_account_read cred_shadow_read cred_ssh_private_key_read cred_vault_token_read
credaccess_pam_config_backdoor credaccess_ssh_authorized_keys_modified defense_evasion_binary_truncate_pad
defense_evasion_journald_log_clear drift_new_file_dir_sensitive drift_new_library_in_system_dir
drift_new_library_in_system_dir_daemon evasion_chmod_sensitive evasion_hidden_elf_in_tmp evasion_log_clear
evasion_system_binary_replace execution_motd_hook_exec exfil_usb_mount fim_apparmor_profile_modified
fim_audit_rules_modified fim_binary_replaced_in_system_dir fim_ca_cert_modified fim_containerd_config_modified
fim_docker_config_modified fim_group_write fim_hosts_file_modified fim_init_d_script_written
fim_kubeconfig_written fim_library_replaced fim_network_config_modified fim_passwd_write
fim_passwd_write_daemon fim_polkit_policy_modified fim_private_key_written fim_profile_modified
fim_rc_local_modified fim_resolv_conf_modified fim_selinux_config_modified fim_shadow_write
fim_shadow_write_daemon fim_ssh_key_written fim_ssh_known_hosts_modified fim_sudoers_written
fim_syslog_modified impact_mass_file_deletion_critical impact_raw_disk_write_from_container
initial_web_shell_write integrity_container_runtime_modified integrity_grub_bootloader_write
integrity_kernel_module_from_user_path integrity_ld_cache_write integrity_ld_so_preload_write
integrity_lib_replaced integrity_sysctl_security_disable lateral_shared_volume_exec
lateral_ssh_agent_socket_access mitre_nsswitch_modified owasp_web_suspicious_write persist_apache_conf_write
persist_etc_environment_write persist_etc_profile_write persist_git_hook_write persist_profile_d_write
persist_sshd_config_write persist_systemd_path_unit persist_systemd_timer_created persist_xdg_autostart_write
persistence_at_spool_write persistence_cron_write persistence_etc_init_write persistence_ld_preload_env
persistence_motd_write persistence_pam_modified persistence_shell_rc_write persistence_ssh_authorized_keys
persistence_systemd_new_service persistence_systemd_service_created proc_keys_read ransomware_disk_wipe
ransomware_encrypted_extension ransomware_log_wipe ransomware_ransom_note recon_sudo_privs
rootkit_kernel_image_write rootkit_ld_preload_written rootkit_pam_module_added_daemon rootkit_passwd_modified
rootkit_passwd_modified_daemon rootkit_proc_sysctl_write rootkit_shared_lib_written_to_system
rootkit_ssh_authorized_keys_modified sensitive_file_read sensitive_file_read_daemon sigma_chmod_executable_tmp
sigma_failed_login_syscall_daemon sigma_log_deletion sigma_passwd_shadow_read sigma_passwd_shadow_read_daemon
sigma_proc_sysrq_write sigma_sensitive_file_chmod sigma_sensitive_file_chmod_daemon sigma_utmp_wtmp_modified
sigma_utmp_wtmp_modified_daemon supply_chain_build_tool_rootwrite
`)

// w549ExplicitLegacyOpRules — правила, назвавшие op ЯВНЫМ legacy-набором
// [open, read, write, chmod] (№549): исключение fwupd-hardware-probe называет
// op, и флаг legacyOpsOnly у правила снимается (долг 8.1 / man-db — то же для
// proc_inject_ld_preload_file и supply_chain_pkg_install_etc_write: исключение
// mandb-self называет op). Мутаций они не видят по
// условию, а не по флагу — проверено TestW549_FwupdRulesIgnoreMutations.
var w549ExplicitLegacyOpRules = strings.Fields(`
container_escape_kmem_access mitre_vm_detect_dmi_read rootkit_kcore_access rootkit_proc_modules_read
sigma_cpu_info_access sigma_dev_mem_access sigma_kernel_version_read
proc_inject_ld_preload_file supply_chain_pkg_install_etc_write
`)

func w81FileEventPPID(pid, ppid uint32, comm, path string, op uint8) types.Event {
	e := w81FileEvent(pid, comm, path, op)
	e.PPID = ppid
	return e
}

// (а) Правило без op не видит мутаций, видит open и write. Образцом до №545
// было container_escape_module_access; №545 назвал в нём op (ветка посадки
// модуля), и образцом стало owasp_log_tampering — второй пострадавший ночи H.
func TestWave8_1_LegacyRuleIgnoresMutations(t *testing.T) {
	engine := w81Engine(t)
	for _, op := range w81MutationOps {
		fired := w81Fired(engine.Evaluate(w81FileEvent(4242, "python3", "/var/log/nginx/access.log", op)))
		assert.Falsef(t, fired["owasp_log_tampering"],
			"owasp_log_tampering (без op) обязано молчать на %s", fileOpNames[op])
	}
	fired := w81Fired(engine.Evaluate(w81FileEvent(4242, "python3", "/var/log/nginx/access.log", 2)))
	assert.True(t, fired["owasp_log_tampering"], "write обязан срабатывать, как до item 7")
}

// (б) Правило, назвавшее op, видит мутации по-прежнему (повторяет
// TestWave8_1_LogWipeRulesFireOnRm на уровне флага), а правило без op —
// owasp_log_tampering, второй пострадавший ночи H — молчит на rename, но не на write.
func TestWave8_1_LegacyOpsFlagSplitsByNamingOp(t *testing.T) {
	engine := w81Engine(t)
	for _, id := range w81LogRules {
		r := engine.rulesByID[id]
		require.NotNilf(t, r, "%s не загружено", id)
		assert.Falsef(t, r.legacyOpsOnly, "%s называет file.op и обязано видеть мутации", id)
	}
	mod := engine.rulesByID["owasp_log_tampering"]
	require.NotNil(t, mod)
	assert.True(t, mod.legacyOpsOnly)

	fired := w81Fired(engine.Evaluate(w81FileEvent(4242, "mv", "/var/log/nginx/access.log", w81OpRename)))
	assert.False(t, fired["owasp_log_tampering"], "owasp_log_tampering без op не видит rename")
	assert.True(t, fired["evasion_log_clear"], "evasion_log_clear (op назван) видит rename")
	fired = w81Fired(engine.Evaluate(w81FileEvent(4242, "python3", "/var/log/nginx/access.log", 2)))
	assert.True(t, fired["owasp_log_tampering"], "owasp_log_tampering на write — как до item 7")
}

// ruleNamesFileOp видит op во всех ветках: вложенная подгруппа, синоним,
// исключение, любой оператор.
func TestWave8_1_RuleNamesFileOpAllBranches(t *testing.T) {
	path := RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc/"}}
	cases := []struct {
		name string
		r    Rule
		want bool
	}{
		{"нет op", Rule{Condition: path}, false},
		{"op в условии", Rule{Condition: RuleCondition{Field: "op", Op: OpEquals, Values: []string{"open"}}}, true},
		{"file.op во вложенной подгруппе", Rule{ConditionGroup: &RuleConditionGroup{Operator: "or",
			Conditions: []RuleCondition{path},
			SubGroups: []RuleConditionGroup{{Operator: "and", Conditions: []RuleCondition{
				{Field: "file.op", Op: OpNotIn, Values: []string{"read"}}}}}}}, true},
		{"op только в исключении", Rule{Condition: path, Exceptions: []RuleException{{Name: "x",
			Condition: RuleCondition{Field: "file.op", Op: OpEquals, Values: []string{"rename"}}}}}, true},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, ruleNamesFileOp(&c.r), c.name)
	}
}

// legacyMutationHits — правила с legacyOpsOnly, сработавшие хотя бы на одной
// мутации, и число правил, сработавших на тех же подачах с op=open (чтобы гард
// не был вакуумным: подачи обязаны вообще уметь поднимать правила).
func legacyMutationHits(t *testing.T, engine *RuleEngine) (hits map[string]int, firedOnOpen int) {
	t.Helper()
	hits = map[string]int{}
	rules := engine.byType[types.EventFileAccess]
	for i := range rules {
		r := rules[i]
		if !r.legacyOpsOnly {
			continue
		}
		paths := []string{"/etc/passwd", "/var/log/syslog", "/lib/modules/x/foo.ko"}
		comms := []string{"bash", "dpkg"}
		uids := []uint32{0, 1000}
		for _, c := range extractAllRuleConditions(&r) {
			switch normaliseFieldName(c.Field) {
			case "filename":
				for _, v := range c.Values {
					switch c.Op {
					case OpPrefix:
						paths = append(paths, v+"x")
					case OpContains:
						paths = append(paths, "/x"+v+"x")
					case OpSuffix:
						paths = append(paths, "/x/x"+v)
					default:
						paths = append(paths, v)
					}
				}
			case "comm", "parent_comm":
				comms = append(comms, c.Values...)
			case "uid":
				for _, v := range c.Values {
					if n, err := strconv.Atoi(v); err == nil {
						uids = append(uids, uint32(n))
					}
				}
			}
		}
		single := NewRuleEngine([]Rule{r})
		opened := false
		for _, p := range paths {
			for _, cm := range comms {
				for _, u := range uids {
					e := w81FileEvent(4242, cm, p, 0)
					e.UID = u
					copy(e.ParentComm[:], cm)
					if !opened && len(single.Evaluate(e)) > 0 {
						opened = true
					}
					for _, op := range w81MutationOps {
						e.File = &types.FileEvent{Op: op}
						copy(e.File.Filename[:], p)
						if len(single.Evaluate(e)) > 0 {
							hits[r.ID]++
						}
					}
				}
			}
		}
		if opened {
			firedOnOpen++
		}
	}
	return hits, firedOnOpen
}

// (в) Гард по корпусу rules/: состав правил, видящих мутации, зафиксирован, и
// ни одно правило без op не срабатывает на мутации.
func TestWave8_1_LegacyOpsGuardShippedRuleset(t *testing.T) {
	engine := w81Engine(t)
	var visible []string
	legacy := 0
	for i := range engine.rules {
		r := &engine.rules[i]
		if r.EventType != types.EventFileAccess {
			assert.Falsef(t, r.legacyOpsOnly, "%s: legacyOpsOnly у нефайлового правила", r.ID)
			continue
		}
		if r.legacyOpsOnly {
			legacy++
		} else {
			visible = append(visible, r.ID)
		}
	}
	sort.Strings(visible)
	want := append(append([]string(nil), w81MutationVisibleRules...), w549ExplicitLegacyOpRules...)
	sort.Strings(want)
	assert.Equal(t, want, visible,
		"состав файловых правил, видящих мутации (op 4..7), изменился: правило, назвавшее op, "+
			"добавить в w81MutationVisibleRules решением автора")

	hits, onOpen := legacyMutationHits(t, engine)
	assert.Empty(t, hits, "правила без op сработали на unlink/rename/truncate/rmdir")
	t.Logf("правил без op: %d, из них подачи подняли на open: %d", legacy, onOpen)
	assert.GreaterOrEqual(t, onOpen, legacy/2, "подачи гарда перестали поднимать правила — гард вакуумен")
}

// (г) Мутация встроена: снять флаг у загруженного правила — и гард краснеет.
func TestWave8_1_LegacyOpsGuardCanFail(t *testing.T) {
	engine := w81Engine(t)
	rules := engine.byType[types.EventFileAccess]
	found := false
	for i := range rules {
		if rules[i].ID == "owasp_log_tampering" {
			rules[i].legacyOpsOnly = false
			found = true
		}
	}
	require.True(t, found)
	fired := w81Fired(engine.Evaluate(w81FileEvent(4242, "python3", "/var/log/nginx/access.log", w81OpUnlink)))
	assert.True(t, fired["owasp_log_tampering"], "без флага правило обязано увидеть unlink — иначе (а) держит не флаг")
	// Правило со снятым флагом выпадает из выборки legacyMutationHits, поэтому
	// краснеет вторая половина (в) — состав видящих мутации.
	var visible int
	for i := range rules {
		if !rules[i].legacyOpsOnly {
			visible++
		}
	}
	assert.Equal(t, len(w81MutationVisibleRules)+len(w549ExplicitLegacyOpRules)+1, visible, "мутация обязана изменить состав видящих мутации")
}

// --- Исключения package-manager / apt-planner-dump / package-transient-artifact ---

const (
	w81DpkgPID      uint32 = 95001 // /usr/bin/dpkg
	w81FakeDpkgPID  uint32 = 95002 // cp /usr/bin/dpkg /tmp/dpkg, comm=dpkg
	w81ScriptPID    uint32 = 95003 // maintainer-скрипт, /usr/bin/dash
	w81UUPID        uint32 = 95004 // unattended-upgr, /usr/bin/python3.10
	w81ShellPID     uint32 = 95005 // интерактивный root shell
	w81PreInvokePID uint32 = 95006 // rm, запущенный dpkg --pre-invoke: родитель — dpkg
)

type w81ExeResolver struct{}

func (w81ExeResolver) ResolveExePath(pid uint32) string {
	switch pid {
	case w81DpkgPID:
		return "/usr/bin/dpkg"
	case w81FakeDpkgPID:
		return "/tmp/dpkg"
	case w81ScriptPID:
		return "/usr/bin/dash"
	case w81UUPID:
		return "/usr/bin/python3.10"
	case w81ShellPID:
		return "/usr/bin/bash"
	}
	return "/usr/bin/rm"
}

func w81WithPkgExe(t *testing.T) {
	t.Helper()
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(w81ExeResolver{})
	t.Cleanup(func() { SetExePathResolver(prev.r) })
}

func w81ExcCount(rule, name string) float64 {
	return testutil.ToFloat64(ruleExceptionsTotal.WithLabelValues(rule, name))
}

func TestWave8_1_PackageManagerSuppressed(t *testing.T) {
	w81WithPkgExe(t)
	engine := w81Engine(t)
	before := w81ExcCount("evasion_log_clear", "package-manager")
	for _, op := range w81MutationOps {
		for _, p := range []string{"/var/log/w81-test/a.log", "/lib/modules/x/foo.ko", "/boot/System.map-x", "/etc/w81/x.conf"} {
			fired := w81Fired(engine.Evaluate(w81FileEvent(w81DpkgPID, "dpkg", p, op)))
			for _, id := range append(append([]string(nil), w81LogRules...), "container_escape_module_access") {
				assert.Falsef(t, fired[id], "%s сработало на %s %s от /usr/bin/dpkg", id, fileOpNames[op], p)
			}
		}
	}
	assert.Greater(t, w81ExcCount("evasion_log_clear", "package-manager"), before,
		"подавление обязано считаться в rule_exceptions_total{exception_name=package-manager}")
}

// Спуф: копия dpkg вне системного пути с comm=dpkg — образ не тот, правило срабатывает.
func TestWave8_1_PackageManagerSpoofFires(t *testing.T) {
	w81WithPkgExe(t)
	engine := w81Engine(t)
	fired := w81Fired(engine.Evaluate(w81FileEvent(w81FakeDpkgPID, "dpkg", "/var/log/auth.log", w81OpUnlink)))
	for _, id := range w81LogRules {
		assert.Truef(t, fired[id], "%s обязано сработать на /tmp/dpkg (comm=dpkg)", id)
	}
}

// Потомок dpkg НЕ подавлен по процессу: `dpkg --pre-invoke='rm /var/log/auth.log'`
// даёт rm с родителем dpkg — ось «предок dpkg» отдала бы ему исключение.
func TestWave8_1_DpkgChildIsNotExempt(t *testing.T) {
	w81WithPkgExe(t)
	engine := w81Engine(t)
	fired := w81Fired(engine.Evaluate(w81FileEventPPID(w81PreInvokePID, w81DpkgPID, "rm", "/var/log/auth.log", w81OpUnlink)))
	for _, id := range w81LogRules {
		assert.Truef(t, fired[id], "%s обязано сработать на rm под dpkg --pre-invoke", id)
	}
	fired = w81Fired(engine.Evaluate(w81FileEventPPID(w81PreInvokePID, w81ScriptPID, "rm", "/boot/vmlinuz-5.15.0-191-generic", w81OpUnlink)))
	assert.True(t, fired["impact_mass_file_deletion_critical"], "удаление ядра из /boot срабатывает и под maintainer-скриптом")
}

// Остаток ночи H по объекту: временные артефакты пакетов и дамп планировщика apt.
func TestWave8_1_PackageObjectsSuppressed(t *testing.T) {
	w81WithPkgExe(t)
	engine := w81Engine(t)
	for _, p := range []string{
		"/boot/grub/grub.cfg.new",
		"/lib/modules/5.15.0-198-generic/.fresh-install",
		"/boot/initrd.img-5.15.0-194-generic.dpkg-bak",
		"/etc/default/grub.dpkg-old",
	} {
		fired := w81Fired(engine.Evaluate(w81FileEventPPID(w81ShellPID+100, w81ScriptPID, "rm", p, w81OpUnlink)))
		assert.Falsef(t, fired["impact_mass_file_deletion_critical"], "артефакт пакета %s", p)
	}
	fired := w81Fired(engine.Evaluate(w81FileEvent(w81UUPID, "unattended-upgr", "/var/log/apt/eipp.log.xz", w81OpUnlink)))
	for _, id := range w81LogRules {
		assert.Falsef(t, fired[id], "%s на дампе планировщика apt", id)
	}
	// Тот же python на настоящем журнале apt — срабатывает: исключение по объекту, не по интерпретатору.
	fired = w81Fired(engine.Evaluate(w81FileEvent(w81UUPID, "unattended-upgr", "/var/log/apt/history.log", w81OpUnlink)))
	for _, id := range w81LogRules {
		assert.Truef(t, fired[id], "%s обязано сработать на удаление history.log", id)
	}
	fired = w81Fired(engine.Evaluate(w81FileEventPPID(w81ShellPID+100, w81ScriptPID, "rm", "/boot/grub/grub.cfg", w81OpUnlink)))
	assert.True(t, fired["impact_mass_file_deletion_critical"], "grub.cfg (не .new) срабатывает")
}

// №550 (ночь H2): `rm /etc/sudoers.pre-conffile` под dpkg → sudo.postinst — временная
// копия conffile, снимается объектом. Сам conffile и приманка вне /etc срабатывают.
func TestWave8_1_PreConffileSuppressed(t *testing.T) {
	w81WithPkgExe(t)
	engine := w81Engine(t)
	rmFrom := func(p string) map[string]bool {
		return w81Fired(engine.Evaluate(w81FileEventPPID(w81ShellPID+100, w81ScriptPID, "rm", p, w81OpUnlink)))
	}
	assert.False(t, rmFrom("/etc/sudoers.pre-conffile")["impact_mass_file_deletion_critical"],
		"временная копия conffile под maintainer-скриптом")
	assert.True(t, rmFrom("/etc/sudoers")["impact_mass_file_deletion_critical"],
		"сам /etc/sudoers срабатывает")
	fired := rmFrom("/var/log/auth.log.pre-conffile")
	assert.True(t, fired["impact_mass_file_deletion_critical"], "приманка .pre-conffile вне /etc не исключена")
	assert.True(t, fired["evasion_log_clear"], "у лог-правил .pre-conffile не исключён вовсе")
}

// Положительный контроль item 7 от root shell — все четыре по-прежнему.
func TestWave8_1_RootShellStillFires(t *testing.T) {
	w81WithPkgExe(t)
	engine := w81Engine(t)
	fired := w81Fired(engine.Evaluate(w81FileEvent(w81ShellPID, "rm", "/var/log/w81ctl/a.log", w81OpUnlink)))
	for _, id := range w81LogRules {
		assert.Truef(t, fired[id], "%s на rm от root shell", id)
	}
}

// №547: обновление рантайма контейнеров через apt — dpkg пишет
// /usr/bin/<runtime>.dpkg-new и переименовывает поверх бинаря. От /usr/bin/dpkg
// правило молчит; копия /tmp/dpkg (comm=dpkg), rm/cp от root shell и потомок
// dpkg (--pre-invoke) — срабатывают.
func TestWave8_1_ContainerRuntimePackageManager(t *testing.T) {
	const rule = "integrity_container_runtime_modified"
	w81WithPkgExe(t)
	engine := w81Engine(t)
	const opWrite uint8 = 2
	before := w81ExcCount(rule, "package-manager")
	for _, ev := range []struct {
		path string
		op   uint8
	}{
		{"/usr/bin/containerd.dpkg-new", opWrite},
		{"/usr/bin/containerd.dpkg-new", w81OpRename},
		{"/usr/bin/containerd", w81OpRename},
		{"/usr/bin/runc", w81OpRename},
	} {
		fired := w81Fired(engine.Evaluate(w81FileEvent(w81DpkgPID, "dpkg", ev.path, ev.op)))
		assert.Falsef(t, fired[rule], "%s от /usr/bin/dpkg на %s %s", rule, fileOpNames[ev.op], ev.path)
	}
	assert.Greater(t, w81ExcCount(rule, "package-manager"), before,
		"подавление обязано считаться в rule_exceptions_total{exception_name=package-manager}")

	for _, c := range []struct {
		pid  uint32
		comm string
		why  string
	}{
		{w81FakeDpkgPID, "dpkg", "копия /tmp/dpkg (comm=dpkg)"},
		{w81ShellPID, "cp", "root shell"},
		{w81PreInvokePID, "cp", "потомок dpkg --pre-invoke"},
	} {
		fired := w81Fired(engine.Evaluate(w81FileEventPPID(c.pid, w81DpkgPID, c.comm, "/usr/bin/containerd", opWrite)))
		assert.Truef(t, fired[rule], "%s обязано сработать: %s", rule, c.why)
	}
}
