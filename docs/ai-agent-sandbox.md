# ebpf-guard for AI Agents — Kernel-Level Sandboxing of Autonomous Agents

> Status: kernel enforcement implemented (issue #255). The cgroup-scoped LSM
> allow maps, the `bprm_check_security` exec hook, the `ebpf-guard run` wrapper,
> and Kubernetes label targeting all ship now. On kernels without BPF LSM
> (< 5.7 / no `CONFIG_BPF_LSM`) the same policy runs in userspace audit-only
> mode. This page documents the policy model, kernel enforcement, and the
> semantic ruleset.

## Why

An autonomous AI/coding agent — Claude Code, Aider, Cursor's background agents,
or an in-cluster agent Pod — executes shell commands, reads files, installs
packages, and makes network calls on your behalf. A prompt-injected or simply
over-eager agent can, within its normal permissions:

- read `~/.ssh`, `~/.aws`, `.env`, or a kubeconfig and exfiltrate credentials;
- `curl … | sh` an unreviewed remote payload;
- reach the cloud instance-metadata service (`169.254.169.254`) to harvest
  instance-role credentials;
- `git push` to an attacker-controlled remote;
- write `~/.bashrc`, a cron entry, or `authorized_keys` to persist.

Wrapper-level guardrails (allow/deny lists in the agent process itself) are
bypassable — the agent, or code it runs, can just call the syscall directly.
**ebpf-guard enforces the policy in the kernel**, below the agent, where it
cannot be argued with.

## One engine, two profiles

ebpf-guard already ships a mature *deny-known-bad* threat-detection engine
(collector → correlator → enforcer → LSM). AI-agent containment is the **same
engine with an inverted policy direction**:

| Profile | Direction | Question it answers |
|---|---|---|
| Threat detection (default) | deny-known-bad | "Did something bad happen?" |
| **AI-agent sandbox** (`ai_sandbox`) | **allow-known-good, deny-by-default** | "Is the agent doing only what I permitted?" |

The allow-list direction is not new to the codebase — `profiler.syscall_allowlist`
already learns-then-enforces a per-workload syscall set. The `ai_sandbox` profile
extends that idea from "syscall set per workload" to a **cgroup-scoped positive
policy over exec / file / network** for a designated agent process tree.

## What is *not* covered

This is syscall/file/network policy enforcement — **complementary to, not a
replacement for, VM-level isolation** (gVisor, Firecracker, Kata/microVMs). There
is no in-kernel LLM/prompt inspection.

**Why a microVM stays optional, not built-in.** A microVM is a *different class*
of isolation (a separate or interposed kernel). ebpf-guard runs LSM hooks in the
**host** kernel, so it cannot *become* a microVM — the two are complementary
axes, not substitutes. Bundling one would also break ebpf-guard's positioning
(no kernel module, single binary / DaemonSet) and force a runtime/privilege
change that is an operator's deployment decision. For the semi-trusted,
**unprivileged** agent threat model above, in-kernel enforcement — with the
self-protection prerequisites in the next section — is intended to be a
sufficient boundary on its own. A microVM remains a documented, **optional**
defence-in-depth tier for the residual risk in-kernel LSM cannot cover (a kernel
0-day, or an agent you deliberately granted root / `CAP_BPF`): for that paranoid
tier, run the agent in a microVM *and* apply an `ai_sandbox` profile inside it.

## Threat model

The agent is assumed **semi-trusted**: it runs code you asked for, but its
instructions may be attacker-influenced (prompt injection via a fetched web
page, a poisoned dependency, a malicious repository). The sandbox constrains the
*blast radius* of the agent's process tree — it does not attempt to decide
whether a given instruction was "really" from you.

## Hard prerequisites — the sandboxed workload must be unprivileged

ebpf-guard enforces the policy with LSM hooks **in the host kernel**. That
boundary only holds if the sandboxed workload cannot reach the enforcer. A
process that holds `CAP_BPF`, `CAP_SYS_ADMIN`, or `CAP_SYS_PTRACE`, or that can
write `/sys/fs/bpf` or `/sys/fs/cgroup`, can detach the LSM links, rewrite the
`sandbox_*` maps, move itself out of its cgroup, or `SIGKILL` the agent — and so
defeat enforcement entirely. **For such a workload `enforce` is a false sense of
security, not a boundary.**

Therefore, running an agent under `mode: enforce` has a hard prerequisite:

- **Drop** `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE` (and ideally all caps
  the agent does not genuinely need) from the sandboxed workload.
- **Do not** give the workload write access to `/sys/fs/bpf` or
  `/sys/fs/cgroup` (no bpffs/cgroupfs mounts writable inside its namespaces).
- Prefer `readOnlyRootFilesystem` and `allowPrivilegeEscalation: false`.

In Kubernetes this posture is set by the Pod `securityContext` at admission —
see `deploy/helm/ebpf-guard/values-secure.yaml` for a hardened, cap-dropped
agent-workload example.

### Fail-closed: ebpf-guard never claims enforcement it cannot back

ebpf-guard checks this posture instead of trusting it. At sandbox registration
(and, for the `run` wrapper, before launching the child) it assesses the
target's effective capabilities. If the target is privileged enough to tamper
with the enforcer, ebpf-guard **refuses to claim enforcement**: it emits a loud
warning with the specific reason, downgrades that target to audit-only, and
reports `kernel_enforced=false` (never a silent "enforced"). If the target's
capability set cannot even be read, it fails closed the same way.

```text
WARN ai_sandbox: --enforce downgraded to audit-only — the sandboxed process
  would inherit privileges that can defeat enforcement
  reasons="[target holds CAP_BPF]"
  remediation="launch the agent unprivileged: drop CAP_BPF/CAP_SYS_ADMIN/
  CAP_SYS_PTRACE and deny write access to /sys/fs/bpf and /sys/fs/cgroup"
```

> Because the `ebpf-guard run` child inherits the wrapper's capabilities, a
> `sudo ebpf-guard run --enforce` where those caps are **not** dropped for the
> child will correctly downgrade to audit. This is the intended signal, not a
> bug: enforcement is only genuine once the agent runs unprivileged.

### ebpf-guard's own files are denied by default

Independently of any profile, every compiled profile denies a **baseline** set
of paths so a sandboxed agent cannot weaken its own enforcer by editing
ebpf-guard's hot-reloaded config/rules, its binary, its control socket, or the
kernel tamper surfaces:

`/etc/ebpf-guard`, `/var/lib/ebpf-guard`, `/run/ebpf-guard`,
`/var/run/ebpf-guard`, the installed `ebpf-guard` binary, `/sys/fs/bpf`,
`/sys/kernel/security`, and the directory of the configured `rules_path`.

These are OR'd in on top of the profile's own `denied_paths`, and a deny always
wins over an allow — so listing one of them under `allowed_read_paths` cannot
re-open it. Add your own secrets (`~/.ssh`, cloud creds, `.env`) to the
profile's `denied_paths` for defence-in-depth.

## Configuration

The `ai_sandbox` section defines the positive policy and how targets are
selected. See `config/config.yaml` for a fully commented example.

```yaml
ai_sandbox:
  enabled: true
  mode: audit            # audit (log only) | enforce (deny with -EPERM)
  rules_path: rules/ai-agent/ai-agent.yaml
  dns_refresh_interval: 60s   # re-resolve allowed_domains → egress allow-list; 0 disables
  selector:
    kube_label: "ebpf-guard.io/sandbox-profile"  # Pod label → profile name
    default_profile: "ai-agent"
  profiles:
    - name: ai-agent
      allowed_exec:       [/usr/bin/, /bin/, /usr/local/bin/]
      allowed_read_paths: [/workspace/, /usr/, /lib/, /etc/ssl/]
      allowed_write_paths:[/workspace/scratch/, /tmp/]   # NOT under an allowed_exec prefix
      denied_paths:       [/root/.ssh/, /home/, /.aws/, /.config/gcloud/]
      allowed_exec_pins:                                 # hash-pin trusted binaries (issue #225)
        - path:   /usr/bin/python3
          sha256: 9b74c9897bac770ffc029102a200c5de... # 64-hex SHA-256 of the trusted binary
      allowed_egress_cidrs:[140.82.112.0/20, 151.101.0.0/16]
      allowed_egress_ports:[443]
      allowed_domains:    [github.com, pypi.org, registry.npmjs.org]
      allow_loopback:     false  # opt-in only; see Profile fields below
```

### Profile fields

| Field | Meaning |
|---|---|
| `allowed_exec` | Absolute path prefixes the agent may `exec`. In enforce mode a downloaded/unknown binary outside these prefixes is denied at `exec`. A prefix that is **also writable** is rejected at load time (see [Exec pinning](#exec-pinning-and-the-writable-exec-rule)). |
| `allowed_exec_pins` | Per-binary hash pins: `{path, sha256}`. A pinned path may exec only when the binary's SHA-256 matches, so a swapped/rebuilt binary at that path is denied even though the path is allowed. Shares the allow-hash map with the #225 cosign exec allow-list. |
| `allowed_read_paths` / `allowed_write_paths` | Path prefixes openable for read / write. Everything else is denied in enforce mode. |
| `denied_paths` | Always denied, even if covered by an allow entry — defence-in-depth for secret directories. |
| `allowed_egress_cidrs` / `allowed_egress_ports` | Destination CIDRs / ports the agent may connect to. Empty ports = any port. |
| `allowed_domains` | DNS names the agent may reach. Resolved to A/AAAA records and programmed as egress allow entries — see [DNS-pinned egress](#dns-pinned-egress). |
| `allow_loopback` | Default `false`. When unset, `127.0.0.0/8` / `::1` are treated as normal destinations and must match `allowed_egress_cidrs` (and `allowed_egress_ports`, if set) like any other address. Set `true` only if the agent genuinely needs unrestricted access to every localhost-bound service on the node — `ebpf-guard run` isolates the child by cgroup only, so it shares the host's loopback (issue #274 item 3). |

### Target selection

- **Kubernetes** — label a Pod `ebpf-guard.io/sandbox-profile: ai-agent`; the
  K8s enricher resolves that Pod's cgroup subtree and applies the named profile
  to just those processes.
- **Local** — wrap the agent with `ebpf-guard run`, which creates a fresh
  cgroup per launch, installs the profile for that cgroup ID, and execs the
  child inside it (via `CLONE_INTO_CGROUP`) so it is under policy before it
  runs a single instruction:

  ```bash
  # audit-only: log what would be blocked
  ebpf-guard run --profile ai-agent -- claude

  # enforce: deny with -EPERM
  ebpf-guard run --profile ai-agent --enforce -- bash
  ```

  The `selector.default_profile` field names the profile the wrapper applies
  when `--profile` is omitted.

## Audit vs. enforce

**Start in `audit`.** Audit mode evaluates every rule and policy decision and
logs/alerts on violations, but never returns `-EPERM`. Run your agent through a
representative task set, review the audit alerts, and widen the allow-lists
until benign work is clean. Only then set `mode: enforce`.

This mirrors `enforcer.dry_run` and is the primary mitigation against the main
risk of a deny-by-default sandbox: **over-blocking that bricks the agent**.
Per-profile scoping and a break-glass path (disable the profile / relabel the
Pod) keep an incorrect policy recoverable.

## Exec pinning and the writable-exec rule

`allowed_exec` is a **path-prefix** allow-list. Prefixes alone cannot tell a
legitimate binary from a malicious one dropped at the same path, so agent exec
containment layers two extra defences.

### Reject writable + executable locations

If a location is both writable and executable, the agent can write a binary
there and run it — plain path allow-listing is defeated. `ValidateConfig`
therefore **rejects a profile whose `allowed_exec` prefix overlaps an
`allowed_write_paths` prefix** (either is a path-ancestor of the other, or they
are equal). Keep exec locations read-only and give the agent a separate,
non-executable scratch dir to write to:

```yaml
allowed_exec:        [/usr/bin/, /bin/]          # read-only system binaries
allowed_write_paths: [/workspace/scratch/, /tmp/] # writable, never under an exec prefix
```

A profile like `allowed_exec: [/work]` + `allowed_write_paths: [/work]` fails to
load with a clear error.

### Hash-pinned binaries (`allowed_exec_pins`, stitched with #225)

For binaries whose identity matters — an interpreter, a package manager, a
release artifact — pin them to a content hash:

```yaml
allowed_exec_pins:
  - path:   /usr/bin/python3
    sha256: <64-hex SHA-256 of the trusted build>
```

A pinned path may exec **only** when the running binary's SHA-256 matches the
pin; a swapped or rebuilt binary at that path is denied even though the path is
covered by `allowed_exec`. This is the same allowed-hash map that the #225
cosign/Sigstore exec allow-list populates from CI/CD attestations — the config
form here lets you pin statically, and #225's verifier writes the same
`sandbox_exec_pins` rows dynamically from verified signatures. The in-kernel
digest lookup at `bprm_check` (via the inode+ctime cache) is delivered by #225;
the userspace audit path and the containment harness evaluate the pins today.

### Interpreter caveat

**Exec control binds the *binary*, not what it interprets.** Pinning
`/usr/bin/python3` (or allowing `/bin/bash`, `/usr/bin/node`, …) still lets the
agent run `python3 evil.py`, `bash -c '…'`, `node -e '…'` — the interpreter is
the allowed binary and the script is just data it reads. Do **not** rely on
`allowed_exec` / `allowed_exec_pins` alone to stop malicious *code*; constrain
interpreters through the other dimensions:

- **file policy** — deny reads/writes outside the workspace so a dropped script
  has nowhere to live and nothing sensitive to read;
- **egress policy** — `allowed_egress_cidrs` / `allowed_domains` so an
  interpreted payload cannot exfiltrate or fetch a second stage;
- **the semantic ruleset** — `rules/ai-agent/ai-agent.yaml` flags `curl|sh`,
  reverse shells, and cloud-metadata SSRF regardless of which binary ran them.

## DNS-pinned egress

In-kernel egress enforcement is CIDR/port based, but the addresses behind names
like `github.com` or `pypi.org` rotate across CDN fronts, so a static
`allowed_egress_cidrs` cannot express "let the agent reach github.com". The
**DNS pinner** closes the gap: for every profile that lists `allowed_domains`,
ebpf-guard periodically resolves each name and programs its current A/AAAA
records as single-host (`/32`, `/128`) egress allow entries scoped to that
profile, pruning addresses that drop out of DNS.

- Controlled by `ai_sandbox.dns_refresh_interval` (default `60s`; `0` disables
  DNS pinning and leaves egress to the static `allowed_egress_cidrs` only).
- Deny-by-default is preserved: only names the operator listed are resolved, and
  only their resolved addresses are opened — never a wildcard.
- **Fail-safe:** a transient resolution failure reuses the last-known addresses
  for that domain rather than tearing a working allow-list down.

> **Not a boundary against DNS control.** DNS-pinned egress is an allow-list
> convenience, not a defence against an attacker who controls the resolver or
> the authoritative zone: if they can make an allowed name resolve to an
> attacker-controlled address, that address is pinned. Pair it with
> `allowed_egress_ports` and the semantic egress rules, and prefer static CIDRs
> for the highest-trust destinations.

## How kernel enforcement works

When a cgroup is registered under a profile (by `ebpf-guard run`, or by the K8s
label controller resolving a labelled Pod's cgroup subtree), the LSM hooks in
`bpf/lsm.bpf.c` consult per-cgroup allow maps:

- **file_open** — the opened path must match an `allowed_read_paths` /
  `allowed_write_paths` prefix (write vs. read chosen from the file mode); a
  `denied_paths` prefix always wins. Deny-by-default: anything unlisted is
  refused.
- **bprm_check_security** — the exec'd binary path must match an `allowed_exec`
  prefix, so a downloaded/unknown binary is denied at exec. `allowed_exec_pins`
  additionally binds a path to a content hash via the `sandbox_exec_pins` map
  (see [Exec pinning](#exec-pinning-and-the-writable-exec-rule)).
- **socket_connect** — the destination must fall inside an
  `allowed_egress_cidrs` entry **or a DNS-pinned host entry** derived from
  `allowed_domains` (loopback is treated the same as any other destination
  unless the profile sets `allow_loopback: true`) and, when the profile lists
  `allowed_egress_ports`, match a listed port. Any address family other than
  `AF_INET`/`AF_INET6` (e.g. `AF_UNIX`) is denied outright under an active
  sandbox — it has no IP/port for this policy to match against.

Path matching uses the same FNV-1a prefix walk in kernel and userspace, so a
prefix like `/workspace` allows `/workspace/**` but not a sibling
`/workspaceX`. Every decision is emitted as an `ai_sandbox` audit event
(`sandbox_audit` in audit mode, `sandbox_deny` in enforce mode).

### In-kernel self-protection and escape-primitive containment

The allow-maps constrain what an agent may *reach*; a second set of hooks
constrains what a sandboxed task may do to *break out* or to *disarm the guard
itself*. These act only on tasks inside a sandboxed cgroup, so they never touch
ordinary host processes — the agent (which is never sandboxed) keeps full use of
`bpf()`, `ptrace`, and the rest.

- **task_kill** — a signal from a sandboxed task to a **protected PID** (the
  ebpf-guard agent and its worker tree, registered in `sandbox_protected_pids`)
  is denied. A contained agent cannot `kill -9` the process that constrains it.
  The agent auto-protects itself at load; `Manager.ProtectPID` adds workers.
- **bpf** — the `bpf()` syscall is denied to a sandboxed task. This is the
  **kernel-side lock on the guard's own state (tamper protection):** a contained
  process cannot `BPF_PROG_DETACH` the sandbox LSM links or
  `BPF_MAP_UPDATE`/`BPF_MAP_DELETE` the `sandbox_*` maps to widen its own policy.
  (The kernel already gates `bpf()` behind `CAP_BPF`; this closes the case of a
  sandboxed workload that was handed that capability.)
- **ptrace** (`ptrace_access_check`) — a sandboxed task attaching to or reading
  another process (`PTRACE_ATTACH`, `PTRACE_SEIZE`, `process_vm_readv`) is
  denied, blocking code injection into a neighbour that is outside the sandbox.
- **mount** (`sb_mount`) — `mount(2)` from a sandboxed task is denied, so it
  cannot remap its filesystem view (bind mounts, procfs remounts, overlay
  escapes) to reach around the `file_open` allow-list.
- **kernel-module load** — a sandboxed task that triggers a module load
  (`request_module`) is denied, cutting off the ring-0 escape.
- **io_uring** (`uring_cmd`, `uring_override_creds`, `uring_sqpoll`) — the
  io_uring escape primitives are denied (issue #277 P0). io_uring lets a task
  submit `openat`/`connect`/`read`/`write` through a ring — and, under
  `IORING_SETUP_SQPOLL`, have a **kernel worker thread** execute them, in a task
  context whose cgroup can differ from the submitter's — which sidesteps the
  cgroup-scoped `file_open`/`socket_connect` allow-lists. Denying `uring_sqpoll`
  removes the kernel-thread submission path, `uring_override_creds` removes the
  personality/credential swap, and `uring_cmd` removes `IORING_OP_URING_CMD`
  device passthrough (e.g. NVMe). These hooks require kernel 5.19+/6.0+; where
  they are absent, enforce mode refuses to claim containment unless io_uring is
  disabled system-wide — see [Kernel requirements](#kernel-requirements).
- **hardlink** (`inode_link`) — hardlink creation by a sandboxed task is denied
  (issue #277 P1). This closes an inode-aliasing **read** bypass: an agent can
  `link()` a file it can DAC-read but the profile keeps out of policy into one of
  its readable prefixes, and `bpf_d_path()` then reports the *allowed* alias at
  open, so the read slips past the path allow-list — the classic fapolicyd-class
  gap that deny-by-default (which only covers the write side) does not catch,
  because both names share one inode and only the alias is in policy. Resolving
  the source dentry's real path in-kernel to compare it against the read policy
  is not something `bpf_d_path()` can do from this hook, so the primitive itself
  is denied, exactly like the other escape primitives above. Only hardlinks are
  affected: symlink creation goes through `inode_symlink`, and a symlink open
  re-resolves to the target's real path so `d_path` already reports the
  out-of-policy destination — no legitimate symlink/rename/copy flow is touched.
  Note a sandboxed workload that relies on hardlinking (some package managers,
  e.g. `pnpm`'s content-addressable store) will see `link()` denied in `enforce`;
  it is audited-only in `audit`, so you can observe the impact before enforcing.

Each fires the same `ai_sandbox` audit event (`sandbox_audit` / `sandbox_deny`)
under the `bpf`, `ptrace`, `mount`, `module`, `uring`, `link`, and `task_kill`
hook labels, and follows the profile's `mode`: audited in `audit`, denied with
`-EPERM` in `enforce`. Every hook is best-effort at attach time — a kernel
missing one (e.g. no `lsm/sb_mount`) logs a warning and leaves the others active
rather than failing the whole sandbox.

> **Not covered in-kernel.** `setns(2)` / `unshare(2)` have no stable BPF LSM
> hook; namespace/cgroup migration is caught instead by the existing
> `cgroup_attach_task` escape detector (audit). `denied_paths` already blocks
> writes to `/sys/fs/bpf` and `/sys/kernel/security`, so a sandboxed task cannot
> reach pinned objects through the filesystem either.

> **Egress note.** In-kernel egress enforcement is CIDR/port based. Named
> destinations in `allowed_domains` are handled by [DNS-pinned
> egress](#dns-pinned-egress): the resolver programs their current A/AAAA
> records into the same kernel allow-maps, so `enforce` mode reaches them
> without hand-maintaining CIDRs. The semantic ruleset still surfaces egress
> abuse (metadata SSRF, `git push` over SSH) independently.

## Semantic ruleset (`rules/ai-agent/ai-agent.yaml`)

Even in `audit` mode, the ruleset gives you high-signal detections
expressed in agent terms, tagged `ai-agent` + `sandbox` for easy filtering:

- credential/secret reads — `~/.ssh`, cloud creds, `.env`, kubeconfig,
  `/proc/<pid>/environ`;
- remote-code pipelines — `curl|sh`, `wget|bash`, package-manager installs;
- persistence — writes to shell rc files, cron, systemd units, `authorized_keys`;
- egress abuse — cloud metadata SSRF, `git push` over SSH;
- reverse-/bind-shell tooling.

This ruleset lives at `rules/ai-agent/ai-agent.yaml` — deliberately **outside**
the default rules directory so it never fires unless you opt in. It is loaded on
demand from `ai_sandbox.rules_path` when `ai_sandbox.enabled: true`. The
detections themselves are process-wide (not gated on cgroup membership); the
kernel allow-maps do the cgroup-scoped enforcement while these rules surface the
attempts. On kernels without BPF LSM they still provide agent-aware
observability independently of enforcement.

## Kernel requirements

| Capability | Requirement |
|---|---|
| File / exec / socket **enforcement** (LSM) | Kernel 5.7+ with `CONFIG_BPF_LSM=y` and BTF |
| Self-protection + escape hooks (`task_kill`, `bpf`, `ptrace`, `sb_mount`, `inode_link`) | Kernel 5.7+ with `CONFIG_BPF_LSM=y`; each attaches best-effort |
| **io_uring** escape hooks (`uring_cmd`, `uring_override_creds`, `uring_sqpoll`) | Kernel 5.19+/6.0+ with `CONFIG_BPF_LSM=y`. **Hard prerequisite for `enforce`** unless io_uring is disabled — see below |
| Egress **enforcement** fallback | nftables (covers network only, not exec/file) |
| Semantic **detection** ruleset | Works on any supported kernel |

### io_uring is a hard prerequisite for `enforce`

io_uring is the single biggest bypass of an LSM-based sandbox: a task can drive
`openat`/`connect`/`uring_cmd` — and, via `IORING_SETUP_SQPOLL`, from a kernel
worker thread — **around** the cgroup-scoped `file_open`/`socket_connect` checks.
ebpf-guard closes this two ways, and `enforce` requires **one of them**:

1. **io_uring LSM hooks attach** (kernel 5.19+/6.0+ with `CONFIG_BPF_LSM=y`). The
   `uring_cmd`/`uring_override_creds`/`uring_sqpoll` hooks above deny the escape
   primitives for sandboxed tasks; the file/socket allow-lists then hold because
   io_uring's `openat`/`connect` still traverse the VFS-layer LSM hooks.
2. **io_uring is disabled for the workload** via the `kernel.io_uring_disabled`
   sysctl (`=2` disables it for everyone; `=1` disables it for non-`CAP_SYS_ADMIN`
   tasks, which is sufficient because a `CAP_SYS_ADMIN` agent is already refused
   enforcement as a tamper-capable target). Set it on the node, or per-pod via a
   `securityContext` `sysctls` entry / the container runtime.

If **neither** holds — the kernel lacks the io_uring LSM hooks *and* io_uring is
reachable — `mode: enforce` **downgrades to audit-only** with a clear startup log
(`kernel_enforced=false`), the same fail-closed posture used for a privileged
target. ebpf-guard detects io_uring reachability at load via
`kernel.io_uring_disabled` and never advertises a boundary an agent can step
around. Remediation is logged: set `kernel.io_uring_disabled=2`, or run on a
kernel 5.19+/6.0+ with `CONFIG_BPF_LSM=y`.

On an unsupported kernel, `mode: enforce` degrades to audit-only with a clear
startup log rather than failing closed, and egress may still be constrained via
the nftables fallback. `mode: enforce` also downgrades to audit-only for any
**privileged target** that could tamper with the enforcer — see
[Hard prerequisites](#hard-prerequisites--the-sandboxed-workload-must-be-unprivileged).

## Kubernetes: the unenforced startup window

Kubernetes targeting is informer-driven (see [Target selection](#target-selection)):
`SandboxController` registers a pod's container cgroups under its profile only
**after** the pod informer delivers the pod and `resolveContainerCgroupIDs`
finds its cgroup directories. Those events fire once the kubelet has already
**started the containers** — so between a labelled pod's containers starting
(image entrypoint, init) and enforcement attaching, the workload runs **live but
unsandboxed**. This is a genuine gap, not a bug you can patch away in the
controller: post-hoc cgroup labeling cannot retroactively contain what already
ran, and the informer cannot observe a container before it exists.

ebpf-guard **surfaces** the window rather than pretending it is closed:

- On startup, when K8s label targeting is enabled, a warning is logged noting the
  window exists.
- Each time a pod is placed under a profile after its containers had already
  started, a warning records the measured `unenforced_window` (from
  `pod.Status.StartTime` to enforcement) and the mitigation.
- `SandboxController.UnenforcedWindowStats()` exposes the count of such late
  registrations and the largest observed window for status/metrics.

**Mitigations** (defence in depth — the boundary is still cgroup/LSM once
attached):

1. **Delay the workload past the window.** Gate the agent container behind an
   init container or a readiness/startup probe that holds real work until the
   sandbox is known to be attached, so the entrypoint does nothing sensitive
   during the gap.
2. **Pre-register the cgroup at admission time.** The robust fix is out-of-band
   of the informer: a CRI/OCI `createRuntime`/`prestart` hook (or an
   admission-time cgroup pre-registration) that places the cgroup under the
   profile *before* the container's first instruction runs. This is the only
   approach that closes — rather than shrinks — the window.
3. **Pin the label at admission (issue #277 P2).** A `ValidatingAdmissionPolicy`
   / webhook that forces the sandbox label per namespace both removes the
   opt-out and lets the admission stage drive pre-registration.

Until admission-time pre-registration lands, treat the startup window as part of
the threat model for short-lived or fast-acting workloads and size mitigation 1
accordingly.

## Status (issue #255 sub-tasks)

1. ✅ cgroup-scoped positive policy maps in LSM (file/socket allow semantics).
2. ✅ exec control via `bprm_check_security` (shares the allowed-exec map with
   #225), plus hash-pinned `allowed_exec_pins` and the writable-exec rejection.
3. ✅ `ebpf-guard run` wrapper for local agents.
4. ✅ Kubernetes targeting by label.
5. ✅ `rules/ai-agent/ai-agent.yaml` + `ai_sandbox` config.
6. ✅ Docs + positioning — this page.
7. ✅ Verification harness — agent-misbehavior detection scenarios
   (`attack-sim --ai-agent`) **and** the containment acceptance harness
   (`attack-sim --containment`) covering each escape vector: kill, map-write,
   cgroup-escape, dropped-binary exec.

### In-kernel self-protection (session 2)

- ✅ **Self-protection** — `task_kill` denies a sandboxed task from signalling
  the agent's protected PID tree (`sandbox_protected_pids`).
- ✅ **Escape-primitive containment** — `bpf`, `ptrace_access_check`, `sb_mount`,
  and kernel-module-load hooks deny the break-out syscalls for sandboxed cgroups.
- ✅ **Tamper protection** — the in-kernel `bpf()` deny stops a sandboxed process
  from detaching the sandbox LSM links or rewriting the `sandbox_*` maps; the
  baseline `denied_paths` block the pinned-object filesystem path in parallel.

### Deeper containment + verification (session 3)

- ✅ **Hash/signature-pinned exec** — `allowed_exec_pins` binds a path to a
  content hash via the `sandbox_exec_pins` map, shared with the #225 cosign exec
  allow-list; the writable-exec rejection blocks the drop-and-swap gap at config
  load; the interpreter caveat is documented above.
- ✅ **DNS-pinned egress** — `allowed_domains` are resolved and their A/AAAA
  records programmed into the egress allow-maps, refreshed on
  `dns_refresh_interval`, fail-safe on lookup errors.
- ✅ **Containment acceptance harness** — `attack-sim --containment` asserts the
  reference enforce profile denies every escape vector (and still allows the
  benign control), evaluated against the userspace policy oracle so it runs in
  CI without a kernel:

  ```bash
  ebpf-guard attack-sim --containment          # run the acceptance harness
  ebpf-guard attack-sim --containment --list   # list the vectors
  ```

### Tamper-proof enforce hardening (issue #277)

- ✅ **P0 — io_uring escape vector** — the `uring_cmd`, `uring_override_creds`,
  and `uring_sqpoll` LSM hooks deny io_uring's escape primitives for sandboxed
  cgroups, and `enforce` refuses to claim containment (downgrades to audit-only,
  `kernel_enforced=false`) when io_uring is reachable on a kernel that lacks those
  hooks. See [io_uring is a hard prerequisite for `enforce`](#io_uring-is-a-hard-prerequisite-for-enforce).
- ✅ **P1 — hardlink read-bypass (inode aliasing)** — the `inode_link` LSM hook
  denies hardlink creation for sandboxed tasks, closing the read path where an
  aliased inode is opened via an in-policy name. See
  [In-kernel self-protection and escape-primitive containment](#in-kernel-self-protection-and-escape-primitive-containment)
  and the `contain-hardlink-alias` vector in `attack-sim --containment`.
- ✅ **P1 — Kubernetes unenforced startup window** — surfaced (startup warning,
  per-pod `unenforced_window` measurement, `UnenforcedWindowStats`) with the
  mitigations documented. See
  [Kubernetes: the unenforced startup window](#kubernetes-the-unenforced-startup-window).
- ⏳ **P2 — label trust / `ebpf-guard run` defense-in-depth** — not yet started.
