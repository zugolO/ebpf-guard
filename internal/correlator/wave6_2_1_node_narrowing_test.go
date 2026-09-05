package correlator

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.2.1, finding №220: the k8s node's own daemons cost 13 974 alerts/h
// against a gate of 100/h, and fourteen rules stood at their rate-limiter
// ceiling — which is what made a real host-side token theft invisible (№221).
// Every rule narrowed for that finding is asserted here in both halves, as
// rule В of "Перенос в 6.1…6.4" requires: the node's own traffic must go
// silent, AND the attack the rule exists for must still alert. A narrowing
// that only silences is indistinguishable from deleting the rule, and the
// 6.2 archive shows exactly that failure mode is easy to reach by accident.
//
// The suppressed inputs are not invented: each is the literal path or command
// line taken from server-logs/collect-6.2 (alerts-window-end.json), named per
// case below. This is an internal test (package correlator, not
// correlator_test) because two of the rules read package-level behavioural
// state — globalConnFrequency for conn_rate_1m and globalBurstTracker for
// threshold rules — which an external test cannot prime.

// w621ExeSpoofPID — процесс с тем же comm и тем же хостовым контекстом, у
// которого подделан ТОЛЬКО образ: /proc/<pid>/exe ведёт в /tmp. Это ровно
// сценарий `cp /bin/cat /tmp/k3s-server && exec -a k3s-server /tmp/k3s-server`,
// который слой 1 (ось из cgroup) пропустил бы: на хосте container_id и
// pod_name пусты и у подделки, и у настоящего демона.
const w621ExeSpoofPID uint32 = 93001

type w621ExeResolver struct{}

func (w621ExeResolver) ResolveExePath(pid uint32) string {
	if pid == w621ExeSpoofPID {
		return "/tmp/k3s-server"
	}
	return "/usr/local/bin/k3s"
}

// w621WithExe ставит фиктивный разрешатель образа на время теста. Без него
// поле proc.exe_path пусто (на darwin нет procfs), исключения фона ноды не
// применяются и негативные половины падают — что само по себе и есть проверка
// того, что отказ разрешения открытый: правило срабатывает, а не молчит.
func w621WithExe(t *testing.T) {
	t.Helper()
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(w621ExeResolver{})
	t.Cleanup(func() { SetExePathResolver(prev.r) })
}

// w621At возвращает копию события от имени другого PID — единственный способ
// сменить образ, не трогая ни comm, ни идентичность из cgroup.
func w621At(e types.Event, pid uint32) types.Event {
	e.PID = pid
	return e
}

func w621Rule(t *testing.T, file, id string) *RuleEngine {
	t.Helper()
	w621WithExe(t)
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

// w621Pod is the identity a cgroup-derived enricher attaches. Nil means "host
// context": no container, no pod — which is what every node daemon looks like
// and what an in-pod payload can never fake, however it renames itself.
func w621Pod(namespace, pod string) *types.EnrichmentInfo {
	return &types.EnrichmentInfo{Namespace: namespace, PodName: pod, ContainerID: w621PodCID, RuntimeSource: "k8s"}
}

func w621File(comm, path, containerID string) types.Event {
	e := types.Event{Type: types.EventFileAccess, PID: 4242, File: &types.FileEvent{Op: 0}}
	copy(e.Comm[:], comm)
	copy(e.File.Filename[:], path)
	if containerID != "" {
		e.Enrichment = &types.EnrichmentInfo{ContainerID: containerID}
	}
	return e
}

func w621FileIn(comm, path string, id *types.EnrichmentInfo) types.Event {
	e := w621File(comm, path, "")
	e.Enrichment = id
	return e
}

func w621Net(comm string, dport uint16, daddr string) types.Event {
	e := types.Event{Type: types.EventTCPConnect, PID: 4242, Network: &types.NetworkEvent{Dport: dport, Family: types.AFInet}}
	copy(e.Comm[:], comm)
	copy(e.Network.Daddr[:], net.ParseIP(daddr).To4())
	return e
}

func w621NetIn(comm string, dport uint16, daddr string, id *types.EnrichmentInfo) types.Event {
	e := w621Net(comm, dport, daddr)
	e.Enrichment = id
	return e
}

// execve (nr 59) carrying a command line — the shape both iptables rules read.
func w621Exec(comm, args string) types.Event {
	e := types.Event{Type: types.EventSyscall, PID: 4242, ProcArgs: args, Syscall: &types.SyscallEvent{Nr: 59}}
	copy(e.Comm[:], comm)
	return e
}

const w621PodCID = "b7f1c0d9e2a34c5b8f6d1e0a9c3b7d2e4f5a6b8c9d0e1f2a3b4c5d6e7f8a9b0c"

// ---------------------------------------------------------------------------
// File rules.
// ---------------------------------------------------------------------------

func TestWave6_2_1FileNarrowings(t *testing.T) {
	// A pod's own SA token on disk, as k3s writes it (from the 6.2 archive).
	const kubeletToken = "/var/lib/kubelet/pods/30628e68-e526-44d4-a1be-32ffc3a6c33c/volumes/kubernetes.io~projected/kube-api-access-x8k2p/token"

	t.Run("cis_5_1_3_secret_access", func(t *testing.T) {
		e := w621Rule(t, "../../rules/cis-k8s.yaml", "cis_5_1_3_secret_access")
		// k3s bundles the kubelet: its own walk of every pod's secret dir was
		// 24 alerts in the 6.2 window and helped pin the limiter (№221).
		assert.Empty(t, e.Evaluate(w621File("k3s-server", kubeletToken, "")),
			"the node's own kubelet-equivalent reading a pod token must not alert")
		// The 6.2.1.2 control, at unit level: a host process reading the same
		// path is the post-compromise token sweep the rule exists for.
		assert.NotEmpty(t, e.Evaluate(w621File("w621hostcat", kubeletToken, "")),
			"a host process reading a pod's SA token must still alert (№221)")
		// The bypass an exclusion keyed on comm alone would leave open: a pod
		// with a hostPath mount of /var/lib/kubelet renaming itself
		// "k3s-server" is EXACTLY the attack (T1611 credential sweep), so the
		// exclusion is scoped to host context, which a container cannot claim.
		assert.NotEmpty(t, e.Evaluate(w621FileIn("k3s-server", kubeletToken, w621Pod("default", "evil-7f9"))),
			"a pod renaming itself k3s-server must not inherit the node's silence")
		// Слой 2: тот же comm, тот же хостовой контекст — различить их осью
		// из cgroup нельзя, у обоих она пуста. Подделан только образ
		// (/tmp вместо системного каталога), а его назначает ядро в execve.
		assert.NotEmpty(t, e.Evaluate(w621At(w621File("k3s-server", kubeletToken, ""), w621ExeSpoofPID)),
			"a host process running out of /tmp must not inherit the daemon's silence")
	})

	t.Run("k8s_hostpath_kubelet_access", func(t *testing.T) {
		e := w621Rule(t, "../../rules/k8s-attacks.yaml", "k8s_hostpath_kubelet_access")
		assert.Empty(t, e.Evaluate(w621File("k3s-server", "/var/lib/kubelet/pods/30628e68/etc-hosts", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("w621hostcat", kubeletToken, "")),
			"this is the second rule 6.2.1.2 requires to fire on the host read")
		assert.NotEmpty(t, e.Evaluate(w621FileIn("k3s-server", kubeletToken, w621Pod("default", "evil-7f9"))),
			"a pod renaming itself k3s-server must not inherit the node's silence")
		// Слой 2: тот же comm, тот же хостовой контекст — различить их осью
		// из cgroup нельзя, у обоих она пуста. Подделан только образ
		// (/tmp вместо системного каталога), а его назначает ядро в execve.
		assert.NotEmpty(t, e.Evaluate(w621At(w621File("k3s-server", kubeletToken, ""), w621ExeSpoofPID)),
			"a host process running out of /tmp must not inherit the daemon's silence")
	})

	t.Run("k8s_sa_token_projected_read", func(t *testing.T) {
		e := w621Rule(t, "../../rules/k8s-attacks.yaml", "k8s_sa_token_projected_read")
		// containerd projecting the token into the pod's mount namespace is
		// the mechanism the rule watches being abused, not the abuse (61/window).
		assert.Empty(t, e.Evaluate(w621File("containerd", "/var/run/secrets/kubernetes.io/serviceaccount/token", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("curl", "/var/run/secrets/kubernetes.io/serviceaccount/token", "")))
		assert.NotEmpty(t, e.Evaluate(w621FileIn("containerd", "/var/run/secrets/kubernetes.io/serviceaccount/token", w621Pod("default", "evil-7f9"))),
			"a pod renaming itself containerd must not inherit the CRI daemon's silence")
		// Слой 2: тот же comm, тот же хостовой контекст — различить их осью
		// из cgroup нельзя, у обоих она пуста. Подделан только образ
		// (/tmp вместо системного каталога), а его назначает ядро в execve.
		assert.NotEmpty(t, e.Evaluate(w621At(w621File("containerd", "/var/run/secrets/kubernetes.io/serviceaccount/token", ""), w621ExeSpoofPID)),
			"a host process running out of /tmp must not inherit the daemon's silence")
	})

	t.Run("container_escape_host_mount", func(t *testing.T) {
		e := w621Rule(t, "../../rules/container-escape.yaml", "container_escape_host_mount")
		// 97/window from k3s-server managing /var/lib/kubelet on the host: the
		// rule's name says "container", its condition never checked for one.
		assert.Empty(t, e.Evaluate(w621File("k3s-server", "/var/lib/kubelet/pods/30628e68/volumes", "")))
		assert.Empty(t, e.Evaluate(w621File("containerd", "/var/lib/containerd/io.containerd.runtime/x", "")))
		// From inside a container the same access is the escape it is named for.
		assert.NotEmpty(t, e.Evaluate(w621File("sh", "/var/lib/kubelet/pods/30628e68/volumes", w621PodCID)))
	})

	t.Run("container_escape_host_mount_from_host", func(t *testing.T) {
		// The host half the narrowing would otherwise have deleted, restored as
		// its own warning rule (precedent: правка №200 in wave 6.0f).
		e := w621Rule(t, "../../rules/container-escape.yaml", "container_escape_host_mount_from_host")
		// The runtime's own daemons doing their own work.
		assert.Empty(t, e.Evaluate(w621File("containerd", "/var/lib/containerd/io.containerd.runtime/x", "")))
		assert.Empty(t, e.Evaluate(w621File("k3s-server", "/run/containerd/containerd.sock", "")))
		// A host process reading another container's rootfs: lateral movement.
		assert.NotEmpty(t, e.Evaluate(w621File("tar", "/var/lib/docker/overlay2/abc/diff/etc/shadow", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("cat", "/proc/1/root/etc/shadow", "")))
		// Inside a container the critical rule owns the event — this one must
		// not double-count it into the incident layer.
		assert.Empty(t, e.Evaluate(w621File("tar", "/var/lib/docker/overlay2/abc/diff/etc/shadow", w621PodCID)))
		// /var/lib/kubelet is deliberately out of scope here: cis_5_1_3 and
		// k8s_hostpath_kubelet_access already cover the host read.
		assert.Empty(t, e.Evaluate(w621File("cat", "/var/lib/kubelet/pods/30628e68/volumes/token", "")))
	})

	t.Run("container_escape_host_network", func(t *testing.T) {
		e := w621Rule(t, "../../rules/container-escape.yaml", "container_escape_host_network")
		// 85/window: flannel's iptables child reading its own /proc/net view.
		assert.Empty(t, e.Evaluate(w621File("iptables", "/proc/net/ip_tables_names", "")))
		assert.Empty(t, e.Evaluate(w621File("ip6tables", "/proc/net/ip6_tables_names", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("sh", "/proc/net/ip_tables_names", w621PodCID)))
	})

	t.Run("cryptominer_xmrig_signature", func(t *testing.T) {
		e := w621Rule(t, "../../rules/cryptominer.yaml", "cryptominer_xmrig_signature")
		// Both suppressed paths are verbatim from the 6.2 archive: the bare
		// 'config\.json' pattern matched CoreDNS's projected ConfigMap and
		// local-path-provisioner's own config. That was a condition error, not
		// a threshold (finding №220).
		assert.Empty(t, e.Evaluate(w621File("local-path-prov", "/etc/config/config.json", "")))
		assert.Empty(t, e.Evaluate(w621File("k3s-server",
			"/var/lib/kubelet/pods/30628e68/volumes/kubernetes.io~configmap/config-volume/..2026_09_03_18_51_56.1491204145/config.json", "")))
		// A real miner keeps its config next to the binary, and the binary
		// name itself still matches under any path.
		assert.NotEmpty(t, e.Evaluate(w621File("xmrig", "/opt/xmrig/config.json", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("sh", "/tmp/.x/xmrig", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("sh", "/opt/xmrig/pools.txt", "")))
	})

	t.Run("sigma_log_deletion", func(t *testing.T) {
		e := w621Rule(t, "../../rules/sigma-linux.yaml", "sigma_log_deletion")
		// 243 alerts on the 6.2 run, all under /var/log/pods — k3s rotating
		// pod logs. Suppressed by exception (dropped outright), not by moving
		// the comm into the info-severity twin: criterion 6.2.1.1 sums
		// alerts_total + alerts_filtered_total, so a twin renames volume
		// instead of removing it (wave 5.1's lesson).
		assert.Empty(t, e.Evaluate(w621File("k3s-server",
			"/var/log/pods/kube-system_coredns-54996dc9b4-tq8rc_a581786b/coredns/0.log", "")))
		assert.Empty(t, e.Evaluate(w621File("k3s-server", "/var/log/pods", "")))
		// Scoped to comm AND path: log tampering outside /var/log/pods alerts.
		assert.NotEmpty(t, e.Evaluate(w621File("k3s-server", "/var/log/auth.log", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("sh", "/var/log/pods/kube-system_coredns/coredns/0.log", "")))
		assert.NotEmpty(t, e.Evaluate(w621FileIn("k3s-server", "/var/log/pods/kube-system_coredns/coredns/0.log", w621Pod("default", "evil-7f9"))),
			"a pod renaming itself k3s-server must not get to wipe pod logs silently")

		daemon := w621Rule(t, "../../rules/sigma-linux.yaml", "sigma_log_deletion_daemon")
		assert.Empty(t, daemon.Evaluate(w621File("k3s-server",
			"/var/log/pods/kube-system_coredns-54996dc9b4-tq8rc_a581786b/coredns/0.log", "")),
			"k3s-server must NOT be in the info-severity twin either — that would "+
				"rename the 60 alerts/window, not remove them from the gate")
	})

	t.Run("sigma_cpu_info_access", func(t *testing.T) {
		e := w621Rule(t, "../../rules/sigma-linux.yaml", "sigma_cpu_info_access")
		assert.Empty(t, e.Evaluate(w621File("k3s-server", "/proc/meminfo", "")))
		assert.NotEmpty(t, e.Evaluate(w621FileIn("k3s-server", "/proc/meminfo", w621Pod("default", "evil-7f9"))),
			"the exception is the node's, not the name's")
		// Deliberately still armed: the 6.2 archive shows 6 /proc/cpuinfo reads
		// by k3s-server against 239 of /proc/meminfo, so cpuinfo is not part of
		// the resource-pressure poll and enumeration still alerts.
		assert.NotEmpty(t, e.Evaluate(w621File("k3s-server", "/proc/sys/kernel/osrelease", "")))
	})

	t.Run("sigma_kernel_version_read", func(t *testing.T) {
		e := w621Rule(t, "../../rules/sigma-linux.yaml", "sigma_kernel_version_read")
		assert.Empty(t, e.Evaluate(w621File("k3s-server", "/etc/os-release", "")))
		assert.NotEmpty(t, e.Evaluate(w621FileIn("k3s-server", "/etc/os-release", w621Pod("default", "evil-7f9"))),
			"the exception is the node's, not the name's")
		assert.NotEmpty(t, e.Evaluate(w621File("k3s-server", "/proc/version", "")))
		assert.NotEmpty(t, e.Evaluate(w621File("sh", "/etc/os-release", "")))
	})
}

// ---------------------------------------------------------------------------
// execve rules: both iptables rules matched flannel's chain-membership checks.
// ---------------------------------------------------------------------------

func TestWave6_2_1IptablesNarrowings(t *testing.T) {
	// Verbatim from the 6.2 archive (proc.args of the suppressed alerts).
	flannel := []string{
		"/usr/sbin/iptables -t nat -S FLANNEL-POSTRTG 1 --wait",
		"/usr/sbin/iptables -t nat -C FLANNEL-POSTRTG -m mark --mark 0x4000/0x4000 -m comment --comment flanneld masq -j RETURN --wait",
		"/usr/sbin/iptables -t filter -S FLANNEL-FWD 1 --wait",
		"/usr/sbin/iptables -t filter -C FLANNEL-FWD -s 10.42.0.0/16 -m comment --comment flanneld forward -j ACCEPT --wait",
		"/usr/sbin/iptables -t filter -C FORWARD -m comment --comment flanneld forward -j FLANNEL-FWD --wait",
	}
	realFlush := []string{
		"/usr/sbin/iptables -F",
		"iptables -t nat -F POSTROUTING",
		"iptables --flush",
		"iptables -X FLANNEL-FWD",
		"ip6tables -F",
	}

	for _, tc := range []struct{ file, id string }{
		{"../../rules/defense-evasion.yaml", "evasion_iptables_flush"},
		{"../../rules/sigma-linux.yaml", "sigma_iptables_flush"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			e := w621Rule(t, tc.file, tc.id)
			for _, args := range flannel {
				assert.Empty(t, e.Evaluate(w621Exec("iptables", args)),
					"flannel's chain-membership check is not a flush: %s", args)
			}
			for _, args := range realFlush {
				assert.NotEmpty(t, e.Evaluate(w621Exec("iptables", args)),
					"a real flush must still alert, whoever runs it: %s", args)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Network rules: the node's control-plane and DNS traffic against the attack
// each rule is named for.
// ---------------------------------------------------------------------------

func TestWave6_2_1NetworkNarrowings(t *testing.T) {
	cases := []struct {
		file, id   string
		dport      uint16
		daddr      string
		hostActors []string // excluded only in host context
		podActors  []string // excluded only inside kube-system
		stillFire  string
	}{
		{"../../rules/cryptominer.yaml", "cryptominer_pool_ports", 8080, "10.42.0.10",
			[]string{"k3s-server"}, []string{"coredns"}, "xmrig"},
		{"../../rules/network-intrusion.yaml", "netintr_socks_proxy_port", 8080, "10.42.0.10",
			[]string{"k3s-server"}, []string{"coredns"}, "nc"},
		{"../../rules/initial-access.yaml", "initial_package_postinstall_network", 8080, "10.42.0.10",
			[]string{"k3s-server"}, []string{"coredns"}, "postinst.sh"},
		{"../../rules/exfiltration-extended.yaml", "exfil_large_http_post", 8080, "10.42.0.10",
			[]string{"k3s-server"}, []string{"coredns"}, "curl"},
		{"../../rules/command-and-control.yaml", "beacon_fixed_interval", 4444, "10.42.0.10",
			[]string{"k3s-server"}, []string{"coredns"}, "beacon"},
		{"../../rules/exfiltration-extended.yaml", "exfil_repeated_outbound_to_same_ip", 8080, "10.42.0.10",
			[]string{"k3s-server"}, nil, "tar"},
		{"../../rules/web-attacks-enhanced.yaml", "web_internal_recon", 10250, "10.42.0.10",
			[]string{"k3s-server"}, nil, "php"},
		{"../../rules/webshell-detection.yaml", "webshell_ssrf_internal_network", 10250, "10.42.0.10",
			[]string{"k3s-server"}, nil, "php"},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			e := w621Rule(t, tc.file, tc.id)

			for _, comm := range tc.hostActors {
				// The daemon as it actually runs: on the host, no cgroup identity.
				assert.Empty(t, e.Evaluate(w621NetIn(comm, tc.dport, tc.daddr, nil)),
					"%s: the node's own %s traffic is its normal shape, not the attack", tc.id, comm)
				// The bypass the comm-only exclusion opened: the same name taken
				// by a payload inside a pod. comm is 16 bytes the process sets
				// itself; the pod identity comes from the cgroup, so the
				// exclusion must not follow the name into a container.
				assert.NotEmpty(t, e.Evaluate(w621NetIn(comm, tc.dport, tc.daddr, w621Pod("default", "evil-7f9"))),
					"%s: a pod renaming itself %q must NOT inherit the node's silence", tc.id, comm)
				// Слой 2: тот же comm, тот же хостовой контекст (ось из cgroup
				// пуста у обоих и различить их не может), подделан только
				// образ. exec -a не трогает /proc/<pid>/exe, поэтому
				// исключение не применяется.
				assert.NotEmpty(t, e.Evaluate(w621At(w621NetIn(comm, tc.dport, tc.daddr, nil), w621ExeSpoofPID)),
					"%s: a host process named %q running out of /tmp must NOT inherit the daemon's silence", tc.id, comm)
			}

			for _, comm := range tc.podActors {
				assert.Empty(t, e.Evaluate(w621NetIn(comm, tc.dport, tc.daddr, w621Pod("kube-system", "coredns-54996dc9b4-tq8rc"))),
					"%s: the cluster's own %s pod is its normal shape", tc.id, comm)
				// Same name, another namespace — not the node's DNS pod.
				assert.NotEmpty(t, e.Evaluate(w621NetIn(comm, tc.dport, tc.daddr, w621Pod("default", "coredns"))),
					"%s: %q in another namespace must not inherit kube-system's silence", tc.id, comm)
				// Same name, on the host: a host process is not that pod either.
				assert.NotEmpty(t, e.Evaluate(w621NetIn(comm, tc.dport, tc.daddr, nil)),
					"%s: a host process named %q is not the cluster's DNS pod", tc.id, comm)
			}

			assert.NotEmpty(t, e.Evaluate(w621Net(tc.stillFire, tc.dport, tc.daddr)),
				"%s: the attack this rule is named for must still alert", tc.id)
		})
	}
}

// net_high_frequency_connections reads conn_rate_1m, which lives in
// globalConnFrequency — primed here so the positive half is a real match on
// the rate condition and not an accident of an empty field.
func TestWave6_2_1HighFrequencyNarrowing(t *testing.T) {
	e := w621Rule(t, "../../rules/network-anomaly.yaml", "net_high_frequency_connections")
	now := time.Now()

	prime := func(pid uint32, dport uint16) {
		for i := 0; i < 40; i++ {
			globalConnFrequency.Record(pid, dport, now)
		}
	}

	coredns := w621NetIn("coredns", 53, "10.42.0.10", w621Pod("kube-system", "coredns-54996dc9b4-tq8rc"))
	coredns.PID = 91001
	k3s := w621NetIn("k3s-server", 6443, "10.42.0.10", nil)
	k3s.PID = 91002
	attacker := w621Net("hydra", 3306, "10.42.0.10")
	attacker.PID = 91003
	spoof := w621NetIn("k3s-server", 6443, "10.42.0.10", w621Pod("default", "evil-7f9"))
	spoof.PID = 91004
	prime(coredns.PID, 53)
	prime(k3s.PID, 6443)
	prime(attacker.PID, 3306)
	prime(spoof.PID, 6443)

	assert.Empty(t, e.Evaluate(coredns), "coredns forwarding at cluster volume is not brute force")
	assert.Empty(t, e.Evaluate(k3s), "k3s-server control-plane traffic clears the same threshold by design")
	assert.NotEmpty(t, e.Evaluate(attacker), "a real high-frequency attempt must still alert")
	assert.NotEmpty(t, e.Evaluate(spoof), "a pod renaming itself k3s-server must not inherit the node's silence")
}

// net_portscan_indicator is threshold-gated (5 in 10 s, grouped by pid): the
// excluded comm must stay silent however many probes it makes, and a scanner
// must still cross the threshold.
func TestWave6_2_1PortscanNarrowing(t *testing.T) {
	e := w621Rule(t, "../../rules/network-anomaly.yaml", "net_portscan_indicator")

	probe := func(comm string, pid uint32) types.Event {
		ev := types.Event{
			Type:     types.EventNetClose,
			PID:      pid,
			NetClose: &types.NetworkCloseEvent{Dport: 9200, Family: types.AFInet, Duration: 5 * time.Millisecond},
		}
		copy(ev.Comm[:], comm)
		copy(ev.NetClose.Daddr[:], net.ParseIP("10.42.0.10").To4())
		return ev
	}

	for i := 0; i < 12; i++ {
		assert.Empty(t, e.Evaluate(probe("k3s-server", 92001)),
			"k3s-server's health/readiness probes are scan-shaped by design and must never cross the threshold")
	}

	fired := false
	for i := 0; i < 12 && !fired; i++ {
		fired = len(e.Evaluate(probe("nmap", 92002))) > 0
	}
	assert.True(t, fired, "a real scanner must still cross the 5-in-10s threshold")
}

// countingExeResolver считает обращения к /proc — цена слоя 2 на горячем пути.
type countingExeResolver struct{ n int }

func (c *countingExeResolver) ResolveExePath(uint32) string {
	c.n++
	return "/usr/local/bin/k3s"
}

// Слой 2 стоит один readlinkat на событие, у которого УЖЕ совпало имя демона.
// Держит эту цену не кэш, а порядок условий в исключении: группа "and"
// вычисляется по порядку с коротким замыканием, и условие на exe_path стоит
// последним. Тест фиксирует контракт: событие чужого процесса не должно
// стоить ни одного обращения к /proc. Если кто-нибудь переставит условие в
// YAML наверх, счётчик вырастет и тест упадёт — молча подорожать нельзя.
func TestWave6_2_1ExePathIsNotOnTheHotPath(t *testing.T) {
	c := &countingExeResolver{}
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(c)
	t.Cleanup(func() { SetExePathResolver(prev.r) })

	e := w621Rule(t, "../../rules/cis-k8s.yaml", "cis_5_1_3_secret_access")
	SetExePathResolver(c) // w621Rule ставит свой; вернуть считающий
	const tok = "/var/lib/kubelet/pods/30628e68/volumes/kubernetes.io~projected/kube-api-access-x8k2p/token"

	for i := 0; i < 100; i++ {
		e.Evaluate(w621File("nginx", tok, ""))
	}
	assert.Zero(t, c.n, "события чужих процессов не должны стоить обращения к /proc")

	e.Evaluate(w621File("k3s-server", tok, ""))
	assert.LessOrEqual(t, c.n, 1,
		"на событие демона допустимо не больше одного разрешения образа")
}

// ---------------------------------------------------------------------------
// Слой 3: смена прав переехала на файловую ось.
// ---------------------------------------------------------------------------

// w621Chmod — файловое событие смены прав (FILE_OP_CHMOD = 3). Пустой path
// это fchmod(2) по дескриптору, о котором агент ничего не знает.
func w621Chmod(comm, path string, mode uint32) types.Event {
	e := types.Event{Type: types.EventFileAccess, PID: 4242,
		File: &types.FileEvent{Op: 3, Mode: mode, FDPath: path}}
	copy(e.Comm[:], comm)
	copy(e.File.Filename[:], path)
	return e
}

// w621ChmodRules собирает три правила о смене прав в ОДИН движок: главный
// дефект №220 был не в каждом из них по отдельности, а в том, что все три
// несли одно и то же условие и давали три алерта на один chmod.
func w621ChmodRules(t *testing.T) *RuleEngine {
	t.Helper()
	w621WithExe(t)
	var out []Rule
	for _, src := range []struct {
		file string
		ids  []string
	}{
		{"../../rules/defense-evasion.yaml", []string{"evasion_chmod_sensitive"}},
		{"../../rules/sigma-linux.yaml", []string{
			"sigma_chmod_executable_tmp", "sigma_sensitive_file_chmod",
			"sigma_sensitive_file_chmod_daemon"}},
	} {
		rules, err := LoadRulesFromFile(src.file)
		require.NoError(t, err)
		for _, id := range src.ids {
			found := false
			for i := range rules {
				if rules[i].ID == id {
					out = append(out, rules[i])
					found = true
				}
			}
			require.Truef(t, found, "rule %s missing from %s", id, src.file)
		}
	}
	return NewRuleEngine(out)
}

func w621IDs(alerts []types.Alert) []string {
	ids := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ids = append(ids, a.RuleID)
	}
	return ids
}

func TestWave6_2_1ChmodMovedToFileAxis(t *testing.T) {
	e := w621ChmodRules(t)

	// Сердце находки №220: раньше ЛЮБОЙ chmod поднимал все три правила сразу.
	// Теперь каждое отвечает за своё место, и на одно событие приходится
	// ровно один алерт.
	t.Run("одно событие — одно правило", func(t *testing.T) {
		assert.Equal(t, []string{"sigma_chmod_executable_tmp"},
			w621IDs(e.Evaluate(w621Chmod("sh", "/tmp/.x/payload", 0o755))))
		assert.Equal(t, []string{"evasion_chmod_sensitive"},
			w621IDs(e.Evaluate(w621Chmod("sh", "/usr/bin/curl", 0o4755))))
		assert.Equal(t, []string{"sigma_sensitive_file_chmod"},
			w621IDs(e.Evaluate(w621Chmod("sh", "/etc/shadow", 0o666))))
	})

	// Фон замера 6.2: 41 из 48 chmod в окне сделал systemd, и ни один не был
	// ни в /bin, ни в /tmp, ни на файле учётных данных. Объём уходит потому,
	// что правила стали адресными, а не потому, что кого-то заглушили: у
	// systemd тут нет ни исключения, ни двойника.
	t.Run("фон ноды больше не подходит ни под одно", func(t *testing.T) {
		for _, path := range []string{
			"/run/systemd/units/invocation:docker.service",
			"/var/lib/systemd/timesync/clock",
			"/run/user/0/systemd/units",
		} {
			assert.Empty(t, e.Evaluate(w621Chmod("systemd", path, 0o644)), path)
		}
	})

	// Пакетный менеджер, ставящий бинарь, — исключение по comm, как и было.
	t.Run("установка пакета не алерт", func(t *testing.T) {
		assert.Empty(t, e.Evaluate(w621Chmod("dpkg", "/usr/bin/curl", 0o755)))
	})

	// Двойник демона: sshd на файле учётных данных обязан попасть в info-ветку
	// и НЕ поднимать основное правило — иначе разделение только удваивает.
	t.Run("двойник демона", func(t *testing.T) {
		assert.Equal(t, []string{"sigma_sensitive_file_chmod_daemon"},
			w621IDs(e.Evaluate(w621Chmod("sshd", "/etc/ssh/ssh_host_rsa_key", 0o600))))
	})

	// Неразрешённый путь (fchmod по чужому дескриптору) не подходит ни под
	// один префикс — и это не тихая потеря, а считаемая:
	// ebpf_guard_file_chmod_unresolved_total растёт на каждом таком событии
	// (internal/collector/fileaccess.go).
	t.Run("неразрешённый путь никуда не подходит", func(t *testing.T) {
		assert.Empty(t, e.Evaluate(w621Chmod("sh", "", 0o755)))
	})

	// Старая ось обязана замолчать целиком: если правило осталось бы и там,
	// объём бы не изменился, а критерий 6.2.1.1 считает сумму, а не разность.
	t.Run("syscall-ось больше не поднимает эти правила", func(t *testing.T) {
		for _, nr := range []int64{90, 91, 268} {
			ev := types.Event{Type: types.EventSyscall, PID: 4242,
				Syscall: &types.SyscallEvent{Nr: nr}}
			copy(ev.Comm[:], "sh")
			assert.Empty(t, e.Evaluate(ev), "syscall nr=%d", nr)
		}
	})
}

// ---------------------------------------------------------------------------
// Слой 4: чтение SA-токена внутри пода — поведенческий класс, а не путь.
// ---------------------------------------------------------------------------

func w621RuleByID(t *testing.T, file, id string) Rule {
	t.Helper()
	rules, err := LoadRulesFromFile(file)
	require.NoError(t, err)
	for i := range rules {
		if rules[i].ID == id {
			return rules[i]
		}
	}
	require.FailNowf(t, "rule not found", "%s in %s", id, file)
	return Rule{}
}

// Статическая половина: класс и флаг обязаны стоять оба. Один без другого
// хуже, чем ни одного: class: drift без drift_novel_workload даёт НОВОЙ
// нагрузке поблажку на время её окна обучения, а «новая нагрузка» — это ровно
// то, чем становится атакующий, назвавшийся ранее не встречавшимся именем.
func TestWave6_2_1SATokenIsDriftClass(t *testing.T) {
	for _, id := range []string{"k8s_sa_token_read", "k8s_sa_token_projected_read"} {
		r := w621RuleByID(t, "../../rules/k8s-attacks.yaml", id)
		assert.Equal(t, ClassDrift, r.EffectiveClass(),
			"%s: чтение своего токена подом неразличимо по пути — правило обязано быть поведенческим", id)
		assert.Equal(t, "alert", r.DriftNovelWorkload,
			"%s: без этого флага новая нагрузка молчит всё своё окно обучения — это и есть вход атакующего", id)
		assert.Equal(t, types.SeverityCritical, r.Severity,
			"%s: смена класса не должна понижать severity — это переименовало бы объём, а не убрало", id)
	}
}

// Поведенческая половина: то же чтение того же пути даёт разный исход в
// зависимости от того, читал ли его раньше ЭТОТ работник.
func TestWave6_2_1SATokenDriftBehaviour(t *testing.T) {
	const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	const ruleID = "k8s_sa_token_read"

	read := func(comm string) types.Event {
		e := types.Event{Type: types.EventFileAccess, PID: 4242,
			File:       &types.FileEvent{Op: 1, FDPath: tokenPath},
			Enrichment: w621Pod("default", "app-7f9")}
		copy(e.Comm[:], comm)
		copy(e.File.Filename[:], tokenPath)
		return e
	}

	p := profiler.NewDriftBaselineProfiler(profiler.DriftBaselineConfig{
		Enabled: true, LearningPeriod: 0, MinSamples: 1, PerWorkload: true,
		MaxWorkloads: 100, MaxSignaturesPerWorkload: 64, EnforceDeadlinePeriods: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Приложение пода читает свой токен — так делает всякий клиент Kubernetes,
	// и именно это давало 72 алерта/ч на замере 6.2. Первое чтение учится,
	// последующие обязаны замолчать.
	p.ObserveRule(ruleID, read("myapp"), true)
	quiet := 0
	for i := 0; i < 10; i++ {
		if !p.ObserveRule(ruleID, read("myapp"), true) {
			quiet++
		}
	}
	assert.Equal(t, 10, quiet,
		"повторные чтения собственного токена той же нагрузкой обязаны уходить в базу ВСЕ, "+
			"иначе слой 4 убрал не 72 алерта/ч, а их часть")

	// Оболочка внутри того же пода (kubectl exec) — другой comm, значит другая
	// нагрузка. Её чтение того же файла незнакомо, и флаг не даёт ей отмолчать
	// собственное окно обучения.
	assert.True(t, p.ObserveRule(ruleID, read("sh"), true),
		"чтение токена ранее не встречавшейся нагрузкой обязано подниматься немедленно — это T1528")

	// Отказ открытый: выключенный профилировщик возвращает прежнее поведение,
	// то есть прежний шум, а не тишину.
	off := profiler.NewDriftBaselineProfiler(profiler.DriftBaselineConfig{Enabled: false},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.True(t, off.ObserveRule(ruleID, read("myapp"), true),
		"при выключенном профилировщике правило обязано работать как раньше")
}
