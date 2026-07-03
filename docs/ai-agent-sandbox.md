# ebpf-guard for AI Agents — Kernel-Level Sandboxing of Autonomous Agents

> Status: foundational config + ruleset (issue #255). Kernel enforcement
> primitives (cgroup-scoped LSM allow maps, the `bprm_check_security` exec hook,
> and the `ebpf-guard run` wrapper) land in follow-up sub-issues. This page
> documents the policy model and the semantic ruleset that ship today.

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
replacement for, VM-level isolation** (gVisor, Firecracker, Kata/microVMs). If
your threat model requires a hard kernel boundary, run the agent in a microVM
*and* apply an `ai_sandbox` profile inside it for defence-in-depth. There is no
in-kernel LLM/prompt inspection.

## Threat model

The agent is assumed **semi-trusted**: it runs code you asked for, but its
instructions may be attacker-influenced (prompt injection via a fetched web
page, a poisoned dependency, a malicious repository). The sandbox constrains the
*blast radius* of the agent's process tree — it does not attempt to decide
whether a given instruction was "really" from you.

## Configuration

The `ai_sandbox` section defines the positive policy and how targets are
selected. See `config/config.yaml` for a fully commented example.

```yaml
ai_sandbox:
  enabled: true
  mode: audit            # audit (log only) | enforce (deny with -EPERM)
  rules_path: rules/ai-agent.yaml
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
- **Local** — list the agent's entry-point `comm` names under `selector.comms`;
  matching process trees inherit `default_profile`. (The dedicated
  `ebpf-guard run --profile ai-agent -- <cmd>` wrapper, which creates a fresh
  cgroup per launch, is tracked as a follow-up.)

## Audit vs. enforce

**Start in `audit`.** Audit mode evaluates every rule and policy decision and
logs/alerts on violations, but never returns `-EPERM`. Run your agent through a
representative task set, review the audit alerts, and widen the allow-lists
until benign work is clean. Only then set `mode: enforce`.

This mirrors `enforcer.dry_run` and is the primary mitigation against the main
risk of a deny-by-default sandbox: **over-blocking that bricks the agent**.
Per-profile scoping and a break-glass path (disable the profile / relabel the
Pod) keep an incorrect policy recoverable.

## Semantic ruleset (`rules/ai-agent.yaml`)

Even in `audit` mode, `rules/ai-agent.yaml` gives you high-signal detections
expressed in agent terms, tagged `ai-agent` + `sandbox` for easy filtering:

- credential/secret reads — `~/.ssh`, cloud creds, `.env`, kubeconfig,
  `/proc/<pid>/environ`;
- remote-code pipelines — `curl|sh`, `wget|bash`, package-manager installs;
- persistence — writes to shell rc files, cron, systemd units, `authorized_keys`;
- egress abuse — cloud metadata SSRF, `git push` over SSH;
- reverse-/bind-shell tooling.

These load like any other rule set (they respect hot-reload and rate limiting)
and can be used **independently of kernel enforcement** — useful on kernels
without BPF LSM, where they still provide agent-aware observability.

## Kernel requirements

| Capability | Requirement |
|---|---|
| File / exec / socket **enforcement** (LSM) | Kernel 5.7+ with `CONFIG_BPF_LSM=y` and BTF |
| Egress **enforcement** fallback | nftables (covers network only, not exec/file) |
| Semantic **detection** ruleset | Works on any supported kernel |

On an unsupported kernel, `mode: enforce` degrades to audit-only with a clear
startup log rather than failing closed, and egress may still be constrained via
the nftables fallback.

## Roadmap (issue #255 sub-tasks)

1. cgroup-scoped positive policy maps in LSM (file/socket allow semantics).
2. exec control via `bprm_check_security` (shares the allowed-exec map with #225).
3. `ebpf-guard run` wrapper for local agents.
4. Kubernetes targeting by label.
5. **`rules/ai-agent.yaml` + `ai_sandbox` config — delivered here.**
6. Docs + positioning — this page.
7. Verification harness — agent-misbehavior scenarios in `internal/attacker`.
