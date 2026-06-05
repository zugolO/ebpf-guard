package correlator

// Integration tests for the new detection rule sets:
//   rules/process-injection.yaml
//   rules/supply-chain.yaml
//   rules/data-exfiltration.yaml
//   rules/k8s-attacks.yaml
//   rules/privesc.yaml (additional rules)
//
// Each test loads the YAML file then fires a synthetic event that MUST match,
// and a non-matching event that MUST NOT match.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (prefixed with "nr" to avoid collisions with enforcement_test.go)
// ─────────────────────────────────────────────────────────────────────────────

func nrLoadRules(t *testing.T, path string) *RuleEngine {
	t.Helper()
	rules, err := LoadRulesFromFile(path)
	require.NoError(t, err, "failed to load %s", path)
	return NewRuleEngine(rules)
}

func nrAlertIDs(alerts []types.Alert) []string {
	ids := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ids = append(ids, a.RuleID)
	}
	return ids
}

func nrSyscall(nr int64) types.Event {
	return types.Event{
		Type:      types.EventSyscall,
		Timestamp: 1,
		PID:       42,
		Syscall:   &types.SyscallEvent{Nr: nr},
	}
}

func nrFile(path string) types.Event {
	fe := &types.FileEvent{}
	copy(fe.Filename[:], path)
	return types.Event{
		Type:      types.EventFileAccess,
		Timestamp: 1,
		PID:       42,
		File:      fe,
	}
}

func nrNetwork(dport uint16) types.Event {
	return types.Event{
		Type:      types.EventTCPConnect,
		Timestamp: 1,
		PID:       42,
		Network:   &types.NetworkEvent{Dport: dport, Sport: 54321, Proto: 6},
	}
}

func nrDNS(qname string, qtype uint16) types.Event {
	return types.Event{
		Type:      types.EventDNS,
		Timestamp: 1,
		PID:       42,
		DNS:       &types.DNSEvent{QName: qname, QType: qtype},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Category A: Process Injection
// ─────────────────────────────────────────────────────────────────────────────

func TestProcessInjection_PtraceDetected(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrSyscall(101)) // ptrace
	assert.NotEmpty(t, alerts, "ptrace syscall should trigger proc_inject_ptrace")
	assert.Contains(t, nrAlertIDs(alerts), "proc_inject_ptrace")
}

func TestProcessInjection_PtraceNoFire_UnrelatedSyscall(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrSyscall(0)) // read — unrelated
	assert.Empty(t, alerts, "read syscall must not trigger any process-injection rule")
}

func TestProcessInjection_MemfdCreate(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrSyscall(319)) // memfd_create
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "proc_inject_memfd_create")
}

func TestProcessInjection_Fexecve(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrSyscall(322)) // execveat / fexecve
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "proc_inject_fexecve")
}

func TestProcessInjection_ProcMemWrite(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrFile("/proc/1234/mem"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "proc_inject_proc_mem_write")
}

func TestProcessInjection_LdPreloadFile(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrFile("/etc/ld.so.preload"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "proc_inject_ld_preload_file")
}

func TestProcessInjection_DevShmSo(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrFile("/dev/shm/evil.so"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "proc_inject_devshm_so")
}

func TestProcessInjection_SafeFile_NoAlert(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrFile("/usr/lib/libc.so.6"))
	assert.Empty(t, alerts, "/usr/lib/libc.so.6 must not trigger any injection rule")
}

func TestProcessInjection_ProcMapsRecon(t *testing.T) {
	re := nrLoadRules(t, "../../rules/process-injection.yaml")

	alerts := re.Evaluate(nrFile("/proc/1000/maps"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "proc_inject_maps_recon")
}

// ─────────────────────────────────────────────────────────────────────────────
// Category B: Privilege Escalation (new rules added to privesc.yaml)
// ─────────────────────────────────────────────────────────────────────────────

func TestPrivesc_SetnsDetected(t *testing.T) {
	re := nrLoadRules(t, "../../rules/privesc.yaml")

	alerts := re.Evaluate(nrSyscall(308)) // setns
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "privesc_setns_syscall")
}

func TestPrivesc_UnshareDetected(t *testing.T) {
	re := nrLoadRules(t, "../../rules/privesc.yaml")

	alerts := re.Evaluate(nrSyscall(272)) // unshare
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "privesc_unshare_user_ns")
}

func TestPrivesc_CgroupNotifyOnRelease(t *testing.T) {
	re := nrLoadRules(t, "../../rules/privesc.yaml")

	alerts := re.Evaluate(nrFile("/sys/fs/cgroup/memory/notify_on_release"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "privesc_cgroup_notify_on_release")
}

func TestPrivesc_CgroupReleaseAgent(t *testing.T) {
	re := nrLoadRules(t, "../../rules/privesc.yaml")

	alerts := re.Evaluate(nrFile("/sys/fs/cgroup/rdma/release_agent"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "privesc_cgroup_notify_on_release")
}

func TestPrivesc_SuidSuspiciousPath(t *testing.T) {
	re := nrLoadRules(t, "../../rules/privesc.yaml")

	alerts := re.Evaluate(nrFile("/tmp/rootkit"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "privesc_suid_suspicious_path")
}

func TestPrivesc_DevShmSuid(t *testing.T) {
	re := nrLoadRules(t, "../../rules/privesc.yaml")

	alerts := re.Evaluate(nrFile("/dev/shm/priv_esc"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "privesc_suid_suspicious_path")
}

func TestPrivesc_NormalSyscall_NoAlert(t *testing.T) {
	re := nrLoadRules(t, "../../rules/privesc.yaml")

	// getpid (nr=39) should not trigger any syscall-based privesc rule
	alerts := re.Evaluate(nrSyscall(39))
	assert.Empty(t, alerts, "getpid must not trigger any privesc syscall rule")
}

// ─────────────────────────────────────────────────────────────────────────────
// Category C: Supply Chain
// ─────────────────────────────────────────────────────────────────────────────

func TestSupplyChain_PkgInstallEtcWrite(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	alerts := re.Evaluate(nrFile("/etc/profile.d/backdoor.sh"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "supply_chain_pkg_install_etc_write")
}

func TestSupplyChain_CronDWrite(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	alerts := re.Evaluate(nrFile("/etc/cron.d/malicious"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "supply_chain_pkg_install_etc_write")
}

func TestSupplyChain_TmpStagingShell(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	alerts := re.Evaluate(nrFile("/tmp/payload.sh"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "supply_chain_pkg_tmp_staging")
}

func TestSupplyChain_TmpStagingElf(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	alerts := re.Evaluate(nrFile("/var/tmp/dropper.elf"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "supply_chain_pkg_tmp_staging")
}

func TestSupplyChain_BuildToolSystemWrite(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	alerts := re.Evaluate(nrFile("/usr/bin/injected"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "supply_chain_build_tool_rootwrite")
}

func TestSupplyChain_LockfileRecon(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	alerts := re.Evaluate(nrFile("/app/package-lock.json"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "supply_chain_lockfile_recon")
}

func TestSupplyChain_SafePort443_NoAlert(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	// HTTPS (443) is whitelisted in supply_chain_cicd_runner_network
	alerts := re.Evaluate(nrNetwork(443))
	assert.Empty(t, alerts, "port 443 must not trigger supply_chain_cicd_runner_network")
}

func TestSupplyChain_NonStandardPort_Alert(t *testing.T) {
	re := nrLoadRules(t, "../../rules/supply-chain.yaml")

	// Non-standard port 4444 (reverse shell favourite)
	alerts := re.Evaluate(nrNetwork(4444))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "supply_chain_cicd_runner_network")
}

// ─────────────────────────────────────────────────────────────────────────────
// Category D: Data Exfiltration
// ─────────────────────────────────────────────────────────────────────────────

func TestDataExfil_DnsTxtLongLabel(t *testing.T) {
	re := nrLoadRules(t, "../../rules/data-exfiltration.yaml")

	// qname > 60 chars triggers exfil_dns_txt_long_label
	longName := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"
	alerts := re.Evaluate(nrDNS(longName, 16))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "exfil_dns_txt_long_label")
}

func TestDataExfil_X11SocketAccess(t *testing.T) {
	re := nrLoadRules(t, "../../rules/data-exfiltration.yaml")

	alerts := re.Evaluate(nrFile("/tmp/.X11-unix/X0"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "exfil_x11_socket_access")
}

func TestDataExfil_WaylandSocketAccess(t *testing.T) {
	re := nrLoadRules(t, "../../rules/data-exfiltration.yaml")

	alerts := re.Evaluate(nrFile("/run/user/1000/wayland-0"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "exfil_wayland_socket_access")
}

func TestDataExfil_HighPortOutbound(t *testing.T) {
	re := nrLoadRules(t, "../../rules/data-exfiltration.yaml")

	// Port 31337 is > 10000 and not in the whitelist
	alerts := re.Evaluate(nrNetwork(31337))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "exfil_outbound_high_port")
}

func TestDataExfil_SafeDns_NoAlert(t *testing.T) {
	re := nrLoadRules(t, "../../rules/data-exfiltration.yaml")

	// Short normal domain — must not fire tunneling rules
	alerts := re.Evaluate(nrDNS("example.com", 1)) // A query, short name
	assert.Empty(t, alerts, "short normal domain must not trigger exfil rules")
}

func TestDataExfil_DbNonstandardPort(t *testing.T) {
	re := nrLoadRules(t, "../../rules/data-exfiltration.yaml")

	// MySQL connecting to port 9999 (not in whitelist) → exfil indicator
	alerts := re.Evaluate(nrNetwork(9999))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "exfil_db_nonstandard_port_connect")
}

// ─────────────────────────────────────────────────────────────────────────────
// Category E: Kubernetes Attacks
// ─────────────────────────────────────────────────────────────────────────────

func TestK8sAttacks_SATokenRead(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrFile("/var/run/secrets/kubernetes.io/serviceaccount/token"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_sa_token_read")
}

func TestK8sAttacks_EtcdClientPort(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrNetwork(2379))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_etcd_direct_access")
}

func TestK8sAttacks_EtcdPeerPort(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrNetwork(2380))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_etcd_direct_access")
}

func TestK8sAttacks_ControlPlaneAccess(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrFile("/etc/kubernetes/admin.conf"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_hostpath_kubecfg_access")
}

func TestK8sAttacks_KubeletDirAccess(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrFile("/var/lib/kubelet/pki/kubelet.crt"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_hostpath_kubelet_access")
}

func TestK8sAttacks_RuntimeSocketAccess(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrFile("/run/containerd/containerd.sock"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_runtime_socket_access")
}

func TestK8sAttacks_DockerSocketAccess(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrFile("/var/run/docker.sock"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_runtime_socket_access")
}

func TestK8sAttacks_DockerConfigSecret(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrFile("/var/run/secrets/pull-secret/.dockerconfigjson"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_dockerconfig_secret_read")
}

func TestK8sAttacks_SATokenProjected(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrFile("/run/secrets/kubernetes.io/serviceaccount/token"))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_sa_token_projected_read")
}

func TestK8sAttacks_KubectlAPIPort(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrNetwork(6443))
	assert.NotEmpty(t, alerts)
	assert.Contains(t, nrAlertIDs(alerts), "k8s_kubectl_apiserver_exec")
}

func TestK8sAttacks_SafePort80_NoK8sAlert(t *testing.T) {
	re := nrLoadRules(t, "../../rules/k8s-attacks.yaml")

	alerts := re.Evaluate(nrNetwork(80))
	for _, a := range alerts {
		assert.NotEqual(t, "k8s_etcd_direct_access", a.RuleID, "port 80 must not trigger etcd rule")
		assert.NotEqual(t, "k8s_kubectl_apiserver_exec", a.RuleID, "port 80 must not trigger kubectl rule")
	}
}
