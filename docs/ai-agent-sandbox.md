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
  selector:
    kube_label: "ebpf-guard.io/sandbox-profile"  # Pod label → profile name
    comms: ["claude", "aider"]                    # Local entry-point comm names
    default_profile: "ai-agent"
  profiles:
    - name: ai-agent
      allowed_exec:       [/usr/bin/, /bin/, /usr/local/bin/]
      allowed_read_paths: [/workspace/, /usr/, /lib/, /etc/ssl/]
      allowed_write_paths:[/workspace/, /tmp/]
      denied_paths:       [/root/.ssh/, /home/, /.aws/, /.config/gcloud/]
      allowed_egress_cidrs:[140.82.112.0/20, 151.101.0.0/16]
      allowed_egress_ports:[443]
      allowed_domains:    [github.com, pypi.org, registry.npmjs.org]
```

### Profile fields

| Field | Meaning |
|---|---|
| `allowed_exec` | Absolute path prefixes the agent may `exec`. In enforce mode a downloaded/unknown binary outside these prefixes is denied at `exec`. |
| `allowed_read_paths` / `allowed_write_paths` | Path prefixes openable for read / write. Everything else is denied in enforce mode. |
| `denied_paths` | Always denied, even if covered by an allow entry — defence-in-depth for secret directories. |
| `allowed_egress_cidrs` / `allowed_egress_ports` | Destination CIDRs / ports the agent may connect to. Empty ports = any port. |
| `allowed_domains` | DNS domain suffixes the agent may resolve and reach. |

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

  The `selector.comms` / `default_profile` fields name the profile the wrapper
  applies when `--profile` is omitted.

## Audit vs. enforce

**Start in `audit`.** Audit mode evaluates every rule and policy decision and
logs/alerts on violations, but never returns `-EPERM`. Run your agent through a
representative task set, review the audit alerts, and widen the allow-lists
until benign work is clean. Only then set `mode: enforce`.

This mirrors `enforcer.dry_run` and is the primary mitigation against the main
risk of a deny-by-default sandbox: **over-blocking that bricks the agent**.
Per-profile scoping and a break-glass path (disable the profile / relabel the
Pod) keep an incorrect policy recoverable.

## How kernel enforcement works

When a cgroup is registered under a profile (by `ebpf-guard run`, or by the K8s
label controller resolving a labelled Pod's cgroup subtree), the LSM hooks in
`bpf/lsm.bpf.c` consult per-cgroup allow maps:

- **file_open** — the opened path must match an `allowed_read_paths` /
  `allowed_write_paths` prefix (write vs. read chosen from the file mode); a
  `denied_paths` prefix always wins. Deny-by-default: anything unlisted is
  refused.
- **bprm_check_security** — the exec'd binary path must match an `allowed_exec`
  prefix, so a downloaded/unknown binary is denied at exec.
- **socket_connect** — the destination must fall inside an
  `allowed_egress_cidrs` entry (loopback is always allowed) and, when the
  profile lists `allowed_egress_ports`, match a listed port.

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

Each fires the same `ai_sandbox` audit event (`sandbox_audit` / `sandbox_deny`)
under the `bpf`, `ptrace`, `mount`, `module`, and `task_kill` hook labels, and
follows the profile's `mode`: audited in `audit`, denied with `-EPERM` in
`enforce`. Every hook is best-effort at attach time — a kernel missing one (e.g.
no `lsm/sb_mount`) logs a warning and leaves the others active rather than
failing the whole sandbox.

> **Not covered in-kernel.** `setns(2)` / `unshare(2)` have no stable BPF LSM
> hook; namespace/cgroup migration is caught instead by the existing
> `cgroup_attach_task` escape detector (audit). `denied_paths` already blocks
> writes to `/sys/fs/bpf` and `/sys/kernel/security`, so a sandboxed task cannot
> reach pinned objects through the filesystem either.

> **Egress note.** In-kernel egress enforcement is CIDR/port based.
> `allowed_domains` is applied by the semantic ruleset (detection), not the
> kernel allow-maps — in `enforce` mode, allow the resolver and the resolved
> CIDRs, or keep DNS-based allow-listing to audit mode.

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
| Self-protection + escape hooks (`task_kill`, `bpf`, `ptrace`, `sb_mount`) | Kernel 5.7+ with `CONFIG_BPF_LSM=y`; each attaches best-effort |
| Egress **enforcement** fallback | nftables (covers network only, not exec/file) |
| Semantic **detection** ruleset | Works on any supported kernel |

On an unsupported kernel, `mode: enforce` degrades to audit-only with a clear
startup log rather than failing closed, and egress may still be constrained via
the nftables fallback. `mode: enforce` also downgrades to audit-only for any
**privileged target** that could tamper with the enforcer — see
[Hard prerequisites](#hard-prerequisites--the-sandboxed-workload-must-be-unprivileged).

## Status (issue #255 sub-tasks)

1. ✅ cgroup-scoped positive policy maps in LSM (file/socket allow semantics).
2. ✅ exec control via `bprm_check_security` (shares the allowed-exec map with #225).
3. ✅ `ebpf-guard run` wrapper for local agents.
4. ✅ Kubernetes targeting by label.
5. ✅ `rules/ai-agent/ai-agent.yaml` + `ai_sandbox` config.
6. ✅ Docs + positioning — this page.
7. ✅ Verification harness — agent-misbehavior scenarios in `internal/attacker`
   (`attack-sim --ai-agent`).

### In-kernel self-protection (session 2)

- ✅ **Self-protection** — `task_kill` denies a sandboxed task from signalling
  the agent's protected PID tree (`sandbox_protected_pids`).
- ✅ **Escape-primitive containment** — `bpf`, `ptrace_access_check`, `sb_mount`,
  and kernel-module-load hooks deny the break-out syscalls for sandboxed cgroups.
- ✅ **Tamper protection** — the in-kernel `bpf()` deny stops a sandboxed process
  from detaching the sandbox LSM links or rewriting the `sandbox_*` maps; the
  baseline `denied_paths` block the pinned-object filesystem path in parallel.
