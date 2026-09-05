package correlator_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Stage 1 (P1-6, P1-17, P2-12, P2-14) is a detection-weakening change set:
// every allowlist, self-exception and added comm/loopback filter narrows what
// the agent can see. Quieting an idle host is only a win if the agent still
// detects an actual attack afterwards.
//
// This file is the automated half of "прогон №2": it replays the attack
// signals from the reference attack run against the real rules/ catalog and
// asserts they still fire. If a future noise-reduction edit goes too far, this
// fails instead of silently trading detection for silence.

func loadStage1Rules(t *testing.T) []correlator.Rule {
	t.Helper()
	rules, err := correlator.LoadRulesFromDir("../../rules")
	require.NoError(t, err, "rules/ catalog must load")
	require.GreaterOrEqual(t, len(rules), 500, "unexpectedly few rules loaded")
	return rules
}

func stage1Comm(s string) [16]byte {
	var c [16]byte
	copy(c[:], s)
	return c
}

func netEvent(procComm string, dst string, dport uint16) types.Event {
	ip := net.ParseIP(dst)
	var daddr [16]byte
	if v4 := ip.To4(); v4 != nil {
		copy(daddr[:], v4)
	} else {
		copy(daddr[:], ip.To16())
	}
	family := types.AddressFamily(2) // AF_INET
	if ip.To4() == nil {
		family = types.AddressFamily(10) // AF_INET6
	}
	return types.Event{
		Type: types.EventTCPConnect,
		PID:  4242,
		Comm: stage1Comm(procComm),
		Network: &types.NetworkEvent{
			Daddr:  daddr,
			Dport:  dport,
			Proto:  6,
			Family: family,
		},
	}
}

func stage1FileEvent(procComm, path string, op uint8) types.Event {
	e := types.Event{
		Type: types.EventFileAccess,
		PID:  4242,
		Comm: stage1Comm(procComm),
		File: &types.FileEvent{Op: op},
	}
	copy(e.File.Filename[:], path)
	return e
}

// stage1SyscallEvent builds a syscall event for a given syscall number. Used
// by chmod-family rules (5.9d): chmod/fchmod/fchmodat cannot be observed via
// EventFileAccess at all (the collector never hooks them), only via the raw
// syscall number — see sigma_sensitive_file_chmod and sigma_chmod_executable_tmp.
func stage1SyscallEvent(procComm string, nr int64) types.Event {
	return types.Event{
		Type:    types.EventSyscall,
		PID:     4242,
		Comm:    stage1Comm(procComm),
		Syscall: &types.SyscallEvent{Nr: nr},
	}
}

// firedRules returns the set of rule IDs that alerted for the event.
func firedRules(engine *correlator.RuleEngine, e types.Event) map[string]bool {
	got := make(map[string]bool)
	for _, a := range engine.Evaluate(e) {
		got[a.RuleID] = true
	}
	return got
}

// TestStage1_AttacksStillDetected asserts that the attack traffic from the
// reference run is still caught after the Stage 1 noise reduction.
func TestStage1_AttacksStillDetected(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	testCases := []struct {
		name string
		// anyOf: at least one of these rule IDs must fire.
		anyOf []string
		event types.Event
		// repeat: number of times to evaluate the same event before checking
		// firedRules. Rules gated by threshold{} (5.9.9.Fa:
		// cred_proc_maps_mass_read) need >=Count identical events in the
		// same burst window before they alert; every other case fires on
		// the first, so 0 below defaults to 1.
		repeat int
	}{
		{
			name:  "SSRF: web process reaches cloud metadata endpoint",
			anyOf: []string{"owasp_web_metadata_access"},
			event: netEvent("nginx", "169.254.169.254", 80),
		},
		{
			name:  "SSRF: web process outbound to non-standard port",
			anyOf: []string{"owasp_web_ssrf_outbound"},
			event: netEvent("python", "203.0.113.10", 4444),
		},
		{
			name:  "Brute force: SSH port hit from a foreign host",
			anyOf: []string{"sigma_ssh_many_failed_auth"},
			event: netEvent("hydra", "203.0.113.10", 22),
		},
		{
			name:  "SSH tunnel: ssh client to a non-standard port",
			anyOf: []string{"netintr_ssh_non_standard_port"},
			event: netEvent("ssh", "203.0.113.10", 8022),
		},
		{
			name:  "Credential theft: real /etc/shadow read",
			anyOf: []string{"owasp_web_sensitive_file_read", "sigma_passwd_shadow_read", "sensitive_file_read"},
			event: stage1FileEvent("sqlmap", "/etc/shadow", 0),
		},
		{
			name:  "Credential scraping: /proc/<pid>/mem read",
			anyOf: []string{"cred_proc_maps_mass_read"},
			event: stage1FileEvent("sqlmap", "/proc/1234/mem", 0),
			// cred_proc_maps_mass_read carries threshold{count: 5} (5.9.9.Fa).
			repeat: 5,
		},
		{
			name:  "SSH key theft: real private key read",
			anyOf: []string{"sigma_sensitive_dir_listing"},
			event: stage1FileEvent("curl", "/root/.ssh/id_rsa", 0),
		},
		{
			name:  "Container escape: /proc/1/environ read",
			anyOf: []string{"container_escape_init_proc", "mitre_sandbox_detect_proc_read"},
			event: stage1FileEvent("bash", "/proc/1/environ", 0),
		},
		{
			name:  "Persistence: cron backdoor dropped",
			anyOf: []string{"drift_new_file_dir_sensitive"},
			event: stage1FileEvent("bash", "/etc/cron.d/backdoor", 0),
		},
		{
			// The loopback exclusions added for P2-14 must not blind these
			// rules to the remote case they actually exist for.
			name:  "Reverse shell / exfil to a remote high port",
			anyOf: []string{"owasp_reverse_shell_pattern", "exfil_outbound_high_port"},
			event: netEvent("bash", "203.0.113.10", 44444),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			n := tc.repeat
			if n < 1 {
				n = 1
			}
			var got map[string]bool
			for i := 0; i < n; i++ {
				got = firedRules(engine, tc.event)
			}
			for _, id := range tc.anyOf {
				if got[id] {
					return
				}
			}
			t.Errorf("detection lost: none of %v fired for %q — Stage 1 noise "+
				"reduction went too far and traded detection for silence (fired: %v)",
				tc.anyOf, tc.name, keysOf(got))
		})
	}
}

// TestStage1_LoopbackNotExfiltration asserts the P2-14 acceptance criterion:
// loopback traffic is not classified as exfiltration, and a single connection
// no longer fans out into a wall of contradictory hypotheses.
func TestStage1_LoopbackNotExfiltration(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	// The exact idle-run case: curl polling the agent's own API.
	got := firedRules(engine, netEvent("curl", "127.0.0.1", 19090))

	for _, id := range []string{
		"exfil_db_nonstandard_port_connect",
		"exfil_repeated_outbound_to_same_ip",
		"net_portscan_indicator",
		"netintr_ssh_non_standard_port",
		"owasp_web_ssrf_outbound",
		"supply_chain_cicd_runner_network",
		"webshell_network_connection_web_proc",
		"webshell_outbound_high_port",
	} {
		assert.False(t, got[id],
			"%s fired on a loopback connection — loopback is not exfiltration (P2-14)", id)
	}

	assert.LessOrEqual(t, len(got), 2,
		"one TCP connection raised %d alerts (%v); P2-14 acceptance criterion is <=2",
		len(got), keysOf(got))
}

// TestStage1_P1_6_DaemonWritesDowngradedNotSuppressed pins the plan.md open
// question 10 resolution for P1-6: sshd/cron are the source of ~52% of idle
// alert volume writing to passwd/shadow/utmp during routine login and cron
// accounting. The recommendation explicitly rejects suppressing this via an
// exception ("это редкий высокоценный сигнал" — rare, high-value signal) and
// instead requires downgrading severity for the daemon triple while every
// other process (a real attacker) still gets critical.
//
// sigma_utmp_wtmp_modified_daemon expects info, not warning: wave 5.1
// (замер №2) found it still gave 656 alerts/71min at warning, so its
// severity was corrected — see TestStage1_5_1_ClusterDaemonWritesDowngraded.
// The other three keep the original P1-6 warning level; they weren't part
// of the wave 5.1 cluster.
func TestStage1_P1_6_DaemonWritesDowngradedNotSuppressed(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	const opWrite uint8 = 2

	testCases := []struct {
		name       string
		path       string
		baseRule   string
		daemonRule string
		daemonSev  types.Severity
	}{
		{"passwd", "/etc/passwd", "fim_passwd_write", "fim_passwd_write_daemon", types.SeverityWarning},
		{"shadow", "/etc/shadow", "fim_shadow_write", "fim_shadow_write_daemon", types.SeverityWarning},
		{"passwd-or-shadow (rootkit)", "/etc/passwd", "rootkit_passwd_modified", "rootkit_passwd_modified_daemon", types.SeverityWarning},
		{"utmp", "/var/run/utmp", "sigma_utmp_wtmp_modified", "sigma_utmp_wtmp_modified_daemon", types.Severity("info")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, daemonComm := range []string{"sshd", "cron"} {
				alerts := engine.Evaluate(stage1FileEvent(daemonComm, tc.path, opWrite))
				byID := make(map[string]types.Alert)
				for _, a := range alerts {
					byID[a.RuleID] = a
				}

				if a, ok := byID[tc.baseRule]; ok {
					t.Errorf("%s fired at severity %v for daemon comm %q — must not fire the "+
						"critical base rule for sshd/cron, only the daemon variant",
						tc.baseRule, a.Severity, daemonComm)
				}

				a, ok := byID[tc.daemonRule]
				require.True(t, ok, "%s did not fire for daemon comm %q — the P1-6 daemon "+
					"variant must still alert (open question 10: downgrade, not suppress)",
					tc.daemonRule, daemonComm)
				assert.Equal(t, tc.daemonSev, a.Severity,
					"%s fired at %v for daemon comm %q, want %v",
					tc.daemonRule, a.Severity, daemonComm, tc.daemonSev)
			}

			// A non-daemon process (attacker) must still get the critical base rule.
			alerts := engine.Evaluate(stage1FileEvent("attacker", tc.path, opWrite))
			byID := make(map[string]bool)
			for _, a := range alerts {
				byID[a.RuleID] = true
			}
			assert.True(t, byID[tc.baseRule],
				"%s did not fire for a non-daemon writer — P1-6 must not weaken detection "+
					"of a real attacker writing to %s", tc.baseRule, tc.path)
			assert.False(t, byID[tc.daemonRule],
				"%s fired for a non-daemon writer — the daemon variant must be scoped to sshd/cron only",
				tc.daemonRule)
		})
	}
}

// TestStage1_5_1_ClusterDaemonWritesDowngraded pins plan.md wave 5.1: the
// seven rules found in замер №2 to account for 86% of idle alert volume
// (sshd/cron logging in and running cron jobs tripping the same
// /etc/passwd-adjacent cluster seven times over) are split base/_daemon the
// same way P1-6 split the write-path rules, but at info (not warning) —
// замер №2 showed sigma_utmp_wtmp_modified_daemon at warning still gave 656
// alerts/71min, so a severity-only downgrade does not solve volume for a
// cluster this size.
func TestStage1_5_1_ClusterDaemonWritesDowngraded(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	const opOpen uint8 = 0
	const opWrite uint8 = 2

	testCases := []struct {
		name       string
		path       string
		op         uint8
		baseRule   string
		daemonRule string
	}{
		{"passwd/shadow read", "/etc/passwd", opOpen, "sigma_passwd_shadow_read", "sigma_passwd_shadow_read_daemon"},
		{"PAM config access", "/etc/pam.d/sshd", opOpen, "sigma_failed_login_syscall", "sigma_failed_login_syscall_daemon"},
		{"library load", "/usr/lib/security/pam_unix.so", opOpen, "drift_new_library_in_system_dir", "drift_new_library_in_system_dir_daemon"},
		{"PAM module config", "/etc/pam.d/common-auth", opOpen, "rootkit_pam_module_added", "rootkit_pam_module_added_daemon"},
		{"log touch", "/var/log/auth.log", opOpen, "sigma_log_deletion", "sigma_log_deletion_daemon"},
		{"utmp write", "/var/run/utmp", opWrite, "sigma_utmp_wtmp_modified", "sigma_utmp_wtmp_modified_daemon"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, daemonComm := range []string{"sshd", "cron"} {
				alerts := engine.Evaluate(stage1FileEvent(daemonComm, tc.path, tc.op))
				byID := make(map[string]types.Alert)
				for _, a := range alerts {
					byID[a.RuleID] = a
				}

				if a, ok := byID[tc.baseRule]; ok {
					t.Errorf("%s fired at severity %v for daemon comm %q — must not fire the "+
						"base rule for sshd/cron, only the daemon variant at info",
						tc.baseRule, a.Severity, daemonComm)
				}

				a, ok := byID[tc.daemonRule]
				require.True(t, ok, "%s did not fire for daemon comm %q — the wave 5.1 daemon "+
					"variant must still alert (downgrade, not suppress)",
					tc.daemonRule, daemonComm)
				assert.Equal(t, types.Severity("info"), a.Severity,
					"%s fired at %v for daemon comm %q, want info (wave 5.1 correction: "+
						"warning alone did not cut volume for sigma_utmp_wtmp_modified_daemon)",
					tc.daemonRule, a.Severity, daemonComm)
			}

			// A non-daemon process (attacker) must still get the base rule at its
			// original severity.
			alerts := engine.Evaluate(stage1FileEvent("attacker", tc.path, tc.op))
			byID := make(map[string]bool)
			for _, a := range alerts {
				byID[a.RuleID] = true
			}
			assert.True(t, byID[tc.baseRule],
				"%s did not fire for a non-daemon process — wave 5.1 must not weaken "+
					"detection of a real attacker touching %s", tc.baseRule, tc.path)
			assert.False(t, byID[tc.daemonRule],
				"%s fired for a non-daemon process — the daemon variant must be scoped to sshd/cron only",
				tc.daemonRule)
		})
	}
}

// TestStage1_6_2_1_SensitiveFileChmodOnFileAxis закрепляет слой 3 волны 6.2.1
// и заменяет собой прежний TestStage1_5_9d_SensitiveFileChmodMovedToSyscallAxis.
//
// История в двух шагах. До 5.9d правило стояло на файловой оси и не проверяло
// операцию вовсе: любое open/read/write по /etc/shadow поднимало правило с
// именем "chmod". 5.9d перенесла его на syscall-ось — единственное место, где
// НАСТОЯЩИЙ chmod тогда был виден, — ценой полной потери пути: аргументы
// сисколла это сырые указатели. 6.2.1 (находка №220) сняла эту цену: chmod
// заведён в файловом коллекторе (FILE_OP_CHMOD, bpf/fileaccess.bpf.c) с
// разрешением пути, и правило вернулось на файловую ось уже с ОБОИМИ
// предикатами — и операцией, и путём.
//
// Тест держит три вещи, которые терять нельзя ни при каком следующем переносе:
// операция проверяется, путь проверяется, и разделение волны 5.1 остаётся
// понижением, а не подавлением (sshd/cron идут в info-двойник, а не в тишину).
func TestStage1_6_2_1_SensitiveFileChmodOnFileAxis(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	const opChmod uint8 = 3 // FILE_OP_CHMOD
	const opRead uint8 = 1
	const credPath = "/etc/shadow"

	for _, daemonComm := range []string{"sshd", "cron"} {
		alerts := engine.Evaluate(stage1FileEvent(daemonComm, credPath, opChmod))
		byID := make(map[string]types.Alert)
		for _, a := range alerts {
			byID[a.RuleID] = a
		}

		if a, ok := byID["sigma_sensitive_file_chmod"]; ok {
			t.Errorf("sigma_sensitive_file_chmod fired at severity %v for daemon comm %q — "+
				"must not fire the base rule for sshd/cron, only the daemon variant at info",
				a.Severity, daemonComm)
		}
		a, ok := byID["sigma_sensitive_file_chmod_daemon"]
		require.True(t, ok, "sigma_sensitive_file_chmod_daemon did not fire for daemon comm %q — "+
			"the wave 5.1 daemon variant must still alert (downgrade, not suppress)", daemonComm)
		assert.Equal(t, types.Severity("info"), a.Severity,
			"sigma_sensitive_file_chmod_daemon fired at %v for daemon comm %q, want info", a.Severity, daemonComm)
	}

	// A non-daemon process (attacker) must still get the base rule.
	alerts := engine.Evaluate(stage1FileEvent("attacker", credPath, opChmod))
	byID := make(map[string]bool)
	for _, a := range alerts {
		byID[a.RuleID] = true
	}
	assert.True(t, byID["sigma_sensitive_file_chmod"],
		"sigma_sensitive_file_chmod did not fire for a non-daemon chmod — "+
			"6.2.1 must not weaken chmod detection while restoring the path predicate")
	assert.False(t, byID["sigma_sensitive_file_chmod_daemon"],
		"sigma_sensitive_file_chmod_daemon fired for a non-daemon process — must be scoped to sshd/cron only")

	// Предикат операции: чтение того же файла — это НЕ смена прав. Ровно этот
	// дефект 5.9d и чинила, и он обязан оставаться починенным на новой оси
	// (чтение /etc/shadow покрывают sensitive_file_read и
	// sigma_passwd_shadow_read, отдельно и под своими именами).
	for _, id := range []string{"sigma_sensitive_file_chmod", "sigma_sensitive_file_chmod_daemon"} {
		for _, a := range engine.Evaluate(stage1FileEvent("attacker", credPath, opRead)) {
			assert.NotEqual(t, id, a.RuleID,
				"%s fired on a READ of %s — the operation predicate is gone again", id, credPath)
		}
	}

	// Предикат пути: chmod вне списка учётных файлов этому правилу не
	// принадлежит. До 6.2.1 подходил любой chmod любого файла, и это давало
	// 144 алерта из 1787 в окне замера 6.2 на три правила-близнеца.
	for _, a := range engine.Evaluate(stage1FileEvent("attacker", "/var/lib/systemd/timesync/clock", opChmod)) {
		assert.NotContains(t, a.RuleID, "sensitive_file_chmod",
			"a chmod outside the credential set matched %s — the path predicate is gone again", a.RuleID)
	}

	// Старая ось обязана молчать: если бы правило осталось и на syscall-оси,
	// объём не изменился бы, а критерий 6.2.1.1 считает сумму, а не разность.
	for _, nr := range []int64{90, 91, 268} {
		for _, a := range engine.Evaluate(stage1SyscallEvent("attacker", nr)) {
			assert.NotContains(t, a.RuleID, "chmod",
				"syscall nr=%d still raises %s — the rule lives on two axes at once", nr, a.RuleID)
		}
	}
}

// TestStage1_5_1_ContainerEscapeInitProcDaemon pins the container_escape_init_proc
// split (plan.md wave 5.1): prometheus/grafana reading their own /proc/1/* as
// PID 1 of their container namespace is routine self-introspection, not a
// container escape. Interim axis is proc.comm (not container_id/cgroup —
// that needs wave 6.1's k8s metadata).
func TestStage1_5_1_ContainerEscapeInitProcDaemon(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	const opOpen uint8 = 0

	for _, daemonComm := range []string{"prometheus", "grafana"} {
		alerts := engine.Evaluate(stage1FileEvent(daemonComm, "/proc/1/cmdline", opOpen))
		byID := make(map[string]types.Alert)
		for _, a := range alerts {
			byID[a.RuleID] = a
		}

		if a, ok := byID["container_escape_init_proc"]; ok {
			t.Errorf("container_escape_init_proc fired at severity %v for %q — must not fire "+
				"the base rule, only container_escape_init_proc_daemon at info", a.Severity, daemonComm)
		}
		a, ok := byID["container_escape_init_proc_daemon"]
		require.True(t, ok, "container_escape_init_proc_daemon did not fire for %q", daemonComm)
		assert.Equal(t, types.Severity("info"), a.Severity,
			"container_escape_init_proc_daemon fired at %v for %q, want info", a.Severity, daemonComm)
	}

	// A real container-escape attempt from any other process must still alert
	// at the base rule's severity.
	alerts := engine.Evaluate(stage1FileEvent("bash", "/proc/1/environ", opOpen))
	byID := make(map[string]bool)
	for _, a := range alerts {
		byID[a.RuleID] = true
	}
	assert.True(t, byID["container_escape_init_proc"],
		"container_escape_init_proc did not fire for bash reading /proc/1/environ — "+
			"wave 5.1 must not weaken container escape detection")
	assert.False(t, byID["container_escape_init_proc_daemon"],
		"container_escape_init_proc_daemon fired for a non-daemon process")
}

// TestStage1_Q9_WebFileRulesRequireWebProcess pins closed question 9 (plan.md,
// wave 3, "Специфичность файловых правил"). These rules all claim a web server
// process in their name/description but used to condition on filename alone,
// so a single sshd login read of /etc/passwd raised the whole cluster. The
// audit measured the cost: ~19 850 of 58 045 alerts over four runs came from
// this cluster, only ~8% of them from an attacker.
//
// This is the file-rule twin of TestStage1_NetworkRuleSpecificity (P2-14), and
// like it, it asserts both directions: the daemon no longer matches, the web
// process still does.
func TestStage1_Q9_WebFileRulesRequireWebProcess(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	const opOpen uint8 = 0

	testCases := []struct {
		rule string
		path string
	}{
		{"owasp_web_sensitive_file_read", "/etc/passwd"},
		{"appexploit_lfi_passwd_access", "/etc/passwd"},
		{"appexploit_xxe_file_read", "/etc/passwd"},
		{"webshell_sensitive_file_read", "/etc/passwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.rule, func(t *testing.T) {
			// The idle-run FP: sshd reading /etc/passwd during authentication.
			for _, daemonComm := range []string{"sshd", "cron"} {
				got := firedRules(engine, stage1FileEvent(daemonComm, tc.path, opOpen))
				assert.False(t, got[tc.rule],
					"%s fired for %q reading %s — the rule names a web server process "+
						"but its condition does not check one (Q9)", tc.rule, daemonComm, tc.path)
			}

			// The signal the rule exists for must survive: a web worker
			// reading the same path is exactly LFI/XXE/webshell credential access.
			got := firedRules(engine, stage1FileEvent("nginx", tc.path, opOpen))
			assert.True(t, got[tc.rule],
				"%s did not fire for nginx reading %s — the Q9 comm scoping must "+
					"narrow the rule to web processes, not disable it", tc.rule, tc.path)
		})
	}
}

// TestStage1_NetworkRuleSpecificity asserts the P2-14 fix is real: rules that
// name a specific process role no longer fire for unrelated processes.
func TestStage1_NetworkRuleSpecificity(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	// curl to a remote high port: previously tripped the whole fan-out.
	got := firedRules(engine, netEvent("curl", "203.0.113.10", 3000))

	for _, id := range []string{
		"netintr_ssh_non_standard_port",        // curl is not ssh
		"owasp_web_ssrf_outbound",              // curl is not a web server
		"webshell_network_connection_web_proc", // curl is not a web server
		"supply_chain_cicd_runner_network",     // curl is not a CI runner
		"exfil_db_nonstandard_port_connect",    // curl is not a database
	} {
		assert.False(t, got[id],
			"%s fired for curl — the rule names a process role it does not match (P2-14)", id)
	}
}

// TestStage1_P2_12_WriteRulesRequireWrite pins the P2-12 acceptance criterion
// from both sides: a read-only open must not raise a *_write/*_modified alert,
// and the same path opened for write must still raise it.
//
// The second half matters because these rules are now inert unless the
// fileaccess collector actually emits write events
// (collectors.file_ops.track_write, default false). The rule logic must be
// correct for the deployments that do enable it.
func TestStage1_P2_12_WriteRulesRequireWrite(t *testing.T) {
	engine := correlator.NewRuleEngine(loadStage1Rules(t))

	const (
		opOpen  uint8 = 0
		opWrite uint8 = 2
	)

	testCases := []struct {
		ruleID string
		path   string
		// comm of a process that legitimately opens the path read-only.
		readerComm string
	}{
		{"mitre_nsswitch_modified", "/etc/nsswitch.conf", "curl"},
		{"sigma_utmp_wtmp_modified", "/var/log/wtmp", "sshd"},
		{"sigma_proc_sysrq_write", "/proc/sysrq-trigger", "bash"},
		{"container_escape_proc_write", "/proc/sys/kernel/shmmax", "bash"},
		{"owasp_web_suspicious_write", "/var/www/html/shell.php", "nginx"},
	}

	for _, tc := range testCases {
		t.Run(tc.ruleID, func(t *testing.T) {
			// A read-only open must not be reported as a modification.
			openFired := firedRules(engine, stage1FileEvent(tc.readerComm, tc.path, opOpen))
			assert.False(t, openFired[tc.ruleID],
				"%s fired on a read-only open of %s — this is the P2-12 false positive "+
					"(curl resolving /etc/resolv.conf reported as 'modified')", tc.ruleID, tc.path)

			// An actual write must still be reported.
			writeFired := firedRules(engine, stage1FileEvent("attacker", tc.path, opWrite))
			assert.True(t, writeFired[tc.ruleID],
				"%s no longer fires on a real write to %s — the P2-12 fix must suppress "+
					"opens, not disable the rule", tc.ruleID, tc.path)
		})
	}
}

// TestStage1_P2_12_InertRulesAreReported verifies the startup diagnostic that
// P2-12 asked for: the write-dependent rules must be enumerable so the agent
// can warn when collectors.file_ops.track_write is false (the default) and
// they therefore cannot fire.
func TestStage1_P2_12_InertRulesAreReported(t *testing.T) {
	ids := correlator.RulesRequiringFileOp(loadStage1Rules(t), "write")

	assert.NotEmpty(t, ids,
		"no write-dependent rules detected — the P2-12 conversion to 'op: write' "+
			"should make these enumerable for the startup warning")

	for _, want := range []string{
		"fim_passwd_write",
		"fim_shadow_write",
		"mitre_nsswitch_modified",
		"sigma_utmp_wtmp_modified",
		"container_escape_proc_write",
	} {
		assert.Contains(t, ids, want,
			"%s requires op:write but was not reported as write-dependent", want)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
