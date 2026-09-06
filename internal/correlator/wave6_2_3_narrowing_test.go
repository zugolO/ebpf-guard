package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.2.3, item 5 (finding №247, decision 2). c2_periodic_beacon_pattern
// had no node-background exclusion at all: k3s-server/coredns control-plane
// traffic is periodic BY DESIGN (count>2, cv<0.35 — exactly the rule's own
// condition), so narrowing the periodicity axis further (as №231 already
// tried, on the sibling beacon_fixed_interval) cannot separate it from a real
// beacon. 985 matches/window on both 6.2.2 archives. The fix mirrors
// beacon_fixed_interval's already-proven node-host-daemon/kube-system-pod
// exceptions (rules/command-and-control.yaml) rather than inventing a new
// shape, keyed on cgroup identity + kernel-assigned exe_path, never on comm
// alone — see rules.go's getFieldValue commentary and
// TestWave6_2_1NetworkNarrowings for the same predicate on the sibling rule.
func TestWave6_2_3C2PeriodicBeaconNodeExclusion(t *testing.T) {
	e := w621Rule(t, "../../rules/command-and-control.yaml", "c2_periodic_beacon_pattern")

	globalBeaconInterval = NewBeaconIntervalTracker()
	t.Cleanup(func() { globalBeaconInterval = NewBeaconIntervalTracker() })
	const dport = 4444
	const daddr = "10.42.0.10"
	prime := func(pid uint32) {
		var d [16]byte
		copy(d[:], []byte{10, 42, 0, 10})
		now := time.Now()
		for i := 0; i < 4; i++ {
			globalBeaconInterval.Record(pid, d, dport, now.Add(time.Duration(i)*30*time.Second))
		}
	}
	prime(4242)
	prime(w621ExeSpoofPID)

	// The node's own control-plane daemon, on the host, at its real image —
	// this is the 985/window finding №247 measured on both 6.2.2 archives.
	assert.Empty(t, e.Evaluate(w621NetIn("k3s-server", dport, daddr, nil)),
		"k3s-server's periodic control-plane traffic is periodic by design, not a beacon")
	// coredns's periodic upstream forwarding, inside its own kube-system pod.
	assert.Empty(t, e.Evaluate(w621NetIn("coredns", dport, daddr, w621Pod("kube-system", "coredns-54996dc9b4-tq8rc"))),
		"coredns's own periodic upstream forwarding is not a beacon")

	// The bypass a comm-only exclusion would open: a payload inside a pod
	// naming itself "k3s-server" must not inherit the node's silence — comm
	// is 16 bytes the process assigns itself; container_id/pod_name come
	// from the cgroup and cannot be self-assigned.
	assert.NotEmpty(t, e.Evaluate(w621NetIn("k3s-server", dport, daddr, w621Pod("default", "evil-7f9"))),
		"a pod renaming itself k3s-server must NOT inherit the node's silence")
	// coredns's name taken by a pod outside kube-system.
	assert.NotEmpty(t, e.Evaluate(w621NetIn("coredns", dport, daddr, w621Pod("default", "coredns"))),
		"coredns in another namespace must not inherit kube-system's silence")

	// Layer 2 (unspoofable identity): same comm, same host context (cgroup
	// axis is empty for both and cannot tell them apart) — only the
	// kernel-assigned image differs. exec -a does not touch /proc/<pid>/exe.
	assert.NotEmpty(t, e.Evaluate(w621At(w621NetIn("k3s-server", dport, daddr, nil), w621ExeSpoofPID)),
		"a host process named k3s-server running out of /tmp must NOT inherit the daemon's silence")

	// The attack this rule exists for must still alert.
	assert.NotEmpty(t, e.Evaluate(w621Net("beacon", dport, daddr)),
		"a genuine periodic beacon from an unrelated comm must still alert")
}

// w623Syscall builds a syscall event carrying an optional cgroup-derived
// identity (nil = host context, matching every node daemon's shape).
func w623Syscall(comm string, nr int64, id *types.EnrichmentInfo) types.Event {
	e := types.Event{Type: types.EventSyscall, PID: 4242, Syscall: &types.SyscallEvent{Nr: nr}}
	copy(e.Comm[:], comm)
	e.Enrichment = id
	return e
}

// w623WithParent sets the kernel-read parent identity on an event. ParentComm
// is filled in the BPF program from task_struct->real_parent (bpf/common.h),
// so it is present on every event at no extra cost and — unlike exe_path —
// needs no live /proc read at rule-evaluation time.
func w623WithParent(e types.Event, parentComm string) types.Event {
	copy(e.ParentComm[:], parentComm)
	return e
}

// Wave 6.2.3, item 6 (finding №250, decision 5). Five rules encoded the
// container-runtime exclusion as a literal `comm not_in ["runc", ...]`
// inside their own condition — which matches only the exact string "runc"
// and silently misses the comm the namespace-setup CHILD process actually
// reports, "runc:[1:CHILD]" (and "runc:[2:INIT]") — see W623_NODE_ACTORS in
// wave6.2.3-controls.sh. Because that suppression lived inside the
// condition, not in `exceptions`, it was invisible to
// ebpf_guard_rule_exceptions_total, and the missed variant is exactly the
// shape that reached the incident layer as a false incident_confirmed_attack
// on ordinary container startup (finding №250). The fix: a named
// container-runtime-lifecycle exception, covering the full set of comm
// variants, keyed on cgroup identity (container_id/pod_name empty — the
// runtime runs on the host, not inside the container it is building) plus
// the kernel-assigned exe_path as an anti-spoof second layer, same shape as
// node-host-daemon. A pod that fakes its own comm as "runc" carries a
// non-empty container_id/pod_name and does not inherit the exclusion.
func TestWave6_2_3ContainerRuntimeLifecycleExclusion(t *testing.T) {
	cases := []struct {
		file, id string
		nr       int64
	}{
		{"../../rules/cis-k8s.yaml", "cis_5_2_1_privileged_container", 272},
		{"../../rules/container-escape.yaml", "container_escape_unshare_user", 272},
		{"../../rules/container-escape.yaml", "container_escape_pivot_root", 155},
		{"../../rules/privesc.yaml", "privesc_unshare_user_ns", 272},
		{"../../rules/privesc.yaml", "privesc_setns_syscall", 308},
	}

	// legacyLiteralComms USED TO be excluded unconditionally by each rule's own
	// `comm not_in [...]` condition (5.9.3c). Wave 6.2.3 (open question 7)
	// removed that literal from all four condition_groups: it scoped the rule
	// INVISIBLY (a caller matching the literal produced no match, no alert and
	// no metric — a bypass that left no trace) and SPOOFABLY (one comm string
	// evaded four critical rules outright). The identity now lives entirely in
	// the named exceptions below, where every suppression is counted in
	// ebpf_guard_rule_exceptions_total{exception=...}. The observable contract
	// changed accordingly, and both halves are asserted below: the host-side
	// runtime is still silent, but a POD naming itself "runc" now ALERTS.
	//
	// privesc_setns_syscall keeps its own `comm not_in ["nsenter"]` — a
	// different, deliberate exclusion (see the rule) that this wave leaves be.
	legacyLiteralComms := []string{"runc", "containerd-shim"}

	// newVariantComms are the comm forms finding №250 actually found missing:
	// the runtime's own namespace-setup child reports "runc:[1:CHILD]"/
	// "runc:[2:INIT]" (W623_NODE_ACTORS, wave6.2.3-controls.sh), which the
	// literal "runc" match above never catches. These reach evaluation and
	// are caught by the new container-runtime-lifecycle exception, keyed on
	// cgroup identity ONLY (container.id/k8s.pod empty) — NOT on exe_path.
	//
	// A live check on ebaka2 (06.09.2026, same day as the fix) found the
	// exe_path layer unusable here: "runc:[1:CHILD]"/"runc:[2:INIT]" exit
	// before the async rule-evaluation pipeline gets to them, so
	// resolveExePath's live "/proc/<pid>/exe" readlink returns "" and the
	// documented fail-open (rules.go) means the exe_path condition would
	// NEVER match for a real one of these processes — 0 of 5 real
	// runc:[1:CHILD]/[2:INIT] alerts observed live were suppressed while
	// exe_path was part of the condition; all landed in alerts_total. Long-
	// lived daemons (k3s-server/coredns, node-host-daemon's use case) survive
	// long enough for that read to succeed; this short-lived child does not.
	// So, unlike node-host-daemon, a HOST payload naming itself
	// "runc:[1:CHILD]" DOES inherit the silence here — the same accepted
	// gap as legacyLiteralComms above (open question 7, plan.md) — while a
	// POD process (non-empty container.id/k8s.pod) still does not, since
	// that axis is not self-assignable.
	newVariantComms := []string{"runc:[0:PARENT]", "runc:[1:CHILD]", "runc:[2:INIT]"}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			e := w621Rule(t, tc.file, tc.id)

			for _, comm := range legacyLiteralComms {
				assert.Empty(t, e.Evaluate(w623Syscall(comm, tc.nr, nil)),
					"%s: the container runtime's own %q must not alert on ordinary lifecycle", tc.id, comm)

				// Open question 7, CLOSED by wave 6.2.3. Before the literal was
				// removed from the condition, this event produced NO match at
				// all: a pod could evade four critical rules by naming its
				// process "runc", and nothing anywhere counted the evasion.
				// Now the base condition matches and the exceptions decide —
				// cgroup identity is not self-assignable, so it alerts.
				assert.NotEmpty(t, e.Evaluate(w623Syscall(comm, tc.nr, w621Pod("default", "evil-7f9"))),
					"%s: a pod process named %q must NOT inherit the runtime's silence "+
						"(open question 7 — the literal comm bypass)", tc.id, comm)
			}

			for _, comm := range newVariantComms {
				// The runtime's namespace-setup child on the host — ordinary
				// lifecycle, not an escape. Exercises exactly the comm
				// variant the old literal "runc" match missed (finding №250).
				assert.Empty(t, e.Evaluate(w623Syscall(comm, tc.nr, nil)),
					"%s: the container runtime's own %q must not alert on ordinary lifecycle", tc.id, comm)

				// The bypass a comm-only exclusion would open: an attacker
				// INSIDE a pod naming itself after the runtime. cgroup
				// identity is not self-assignable, so the exception must not
				// follow the name into a container.
				assert.NotEmpty(t, e.Evaluate(w623Syscall(comm, tc.nr, w621Pod("default", "evil-7f9"))),
					"%s: a pod process named %q must NOT inherit the runtime's silence", tc.id, comm)

				// No layer 2 here (see comment above): a host process out of
				// /tmp DOES inherit the silence — accepted, documented gap,
				// not a regression this test should flag.
				assert.Empty(t, e.Evaluate(w621At(w623Syscall(comm, tc.nr, nil), w621ExeSpoofPID)),
					"%s: host-context spoof of %q is accepted-gap silence (no exe_path layer for this exception)", tc.id, comm)
			}

			// ── Open question 2 (CLOSED): the cgroup axis is unstable during
			// container setup, so a second exception keys on the parent. ──
			//
			// This is the case the live run on ebaka2 (06.09.2026) found and
			// no unit test caught, because fixtures were built with a stable
			// Enrichment (nil, or a concrete pod) and never reproduced the
			// race: ONE process, some of whose syscalls carry an empty
			// container.id and some the target container's, because it is the
			// process BUILDING that cgroup membership. pivot_root(2) is the
			// last step of the rootfs switch, so its container.id is filled
			// ALWAYS — container_escape_pivot_root got 0 suppressions out of 2
			// live alerts, systematically, and finding №250 stayed open for it.
			for _, comm := range newVariantComms {
				late := w623WithParent(
					w623Syscall(comm, tc.nr, w621Pod("default", "app-5d8")),
					"runc:[0:PARENT]")
				assert.Empty(t, e.Evaluate(late),
					"%s: %q with cgroup ALREADY bound (the pivot_root/late-setns shape) "+
						"must be suppressed by container-runtime-lineage — this is the "+
						"exact live case container-runtime-lifecycle cannot see", tc.id, comm)
			}

			// The lineage axis must not become a second name-only bypass: the
			// parent has to be a runtime too. A pod process naming itself
			// after the runtime, forked by an ordinary shell, still alerts.
			assert.NotEmpty(t,
				e.Evaluate(w623WithParent(
					w623Syscall("runc:[1:CHILD]", tc.nr, w621Pod("default", "evil-7f9")), "sh")),
				"%s: runtime-looking comm with a non-runtime parent must still alert", tc.id)

			// The attack each rule is named for: an unrelated process on the
			// host performing the same syscall must still alert.
			assert.NotEmpty(t, e.Evaluate(w623Syscall("sh", tc.nr, nil)),
				"%s: a genuine host-side call must still alert", tc.id)

			// …and it must keep alerting when its parent is a runtime: a real
			// escape launched from a `kubectl exec` shell has containerd-shim
			// in its ancestry, so lineage alone may never silence a rule.
			assert.NotEmpty(t,
				e.Evaluate(w623WithParent(w623Syscall("sh", tc.nr, nil), "containerd-shim")),
				"%s: a non-runtime comm under a runtime parent must still alert", tc.id)
		})
	}
}

// Wave 6.2.3, open question 2(б). The same five-second pod-creation window
// that produced the runc noise also raised privesc_setns_syscall four times
// from comm=bridge and comm=loopback — flannel's CNI plugins, for which
// setns(2) is the documented mechanism: the plugin enters the pod's network
// namespace to attach the veth end, then leaves. Finding №250 never named
// them, so decision 5 would never have silenced them; this wave brings them
// into scope under their own exception name so the 6.2.3.2 breakdown shows
// the two sources separately.
//
// All three layers are fields already present in the event — no syscall, no
// /proc read at evaluation time. Unlike runc:[1:CHILD], the cgroup layer is
// STABLE for a CNI plugin: it runs in its caller's host cgroup and only
// enters the pod's network namespace, so it never builds a cgroup membership
// of its own mid-call.
func TestWave6_2_3CNIPluginSetnsExclusion(t *testing.T) {
	e := w621Rule(t, "../../rules/privesc.yaml", "privesc_setns_syscall")
	const setns = 308

	for _, plugin := range []string{"bridge", "loopback", "portmap", "host-local"} {
		assert.Empty(t,
			e.Evaluate(w623WithParent(w623Syscall(plugin, setns, nil), "containerd")),
			"CNI plugin %q invoked by containerd on the host must not alert", plugin)
		assert.Empty(t,
			e.Evaluate(w623WithParent(w623Syscall(plugin, setns, nil), "flanneld")),
			"CNI plugin %q invoked by flanneld on the host must not alert", plugin)

		// Anti-spoof, all three layers independently:
		assert.NotEmpty(t,
			e.Evaluate(w623WithParent(w623Syscall(plugin, setns, nil), "sh")),
			"%q forked by a shell is not a CNI invocation and must alert", plugin)
		assert.NotEmpty(t,
			e.Evaluate(w623WithParent(
				w623Syscall(plugin, setns, w621Pod("default", "evil-7f9")), "containerd")),
			"%q running inside a pod is not a host-side CNI invocation and must alert", plugin)
	}

	// The rule's own reason to exist is untouched: setns from anything that is
	// not a CNI plugin still alerts, whoever its parent is.
	assert.NotEmpty(t,
		e.Evaluate(w623WithParent(w623Syscall("sh", setns, nil), "containerd")),
		"a genuine setns escape attempt must still alert under a runtime parent")
}
