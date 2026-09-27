# Rule Set Revision 7.0 — the 292 `condition-not-matched` rules, re-annotated (2026-09-27)

> Wave 7, item 1 (plan.md). Pure YAML analysis: **no rule, no Go, no BPF changed**. Re-annotates the Z1–Z4 (`silent / condition-not-matched`) set of [revision 3.0](rules-audit-2026-08-06.md) after waves 5–6, and turns the one-shot snapshot into a regenerable table.

## 1. Method and reproducibility

The table is **generated**, not edited. One command from the repo root:

```bash
python3 tools/rules-audit/classify.py
```

It (1) runs `go run ./tools/rules-audit <dir> <out.json>` — a plain YAML reader that records each rule's `id:` line — over the **current working tree** `rules/` and over the 3.0 measurement snapshot `git archive 3a3006a rules`; (2) reads the 292 ids out of the Z1–Z4 per-rule tables of `docs/rules-audit-2026-08-06.md`; (3) joins them, computes the reason/decision below, and writes `docs/rules-audit-2026-09-27.csv` + this file. The script asserts the Z-set is exactly 292 ids, that no id appears in two Z sections, and that the emitted row set equals the Z-set, or it exits non-zero.

Inputs, all in-tree: `docs/rules-audit-2026-08-06.md` (the Z1–Z4 lists), `docs/rules-audit-2026-08-06.csv` (the 3.0 statuses), `rules/*.yaml` at HEAD and at `3a3006a`, and `config/config.yaml` for the in-kernel syscall allowlist (§3) — the script exits non-zero if `kernel_filter.enabled` is not `true` or the allowlist anchor moved, rather than emitting a table against a filter it did not read. Line citations are `file:line` of the current YAML. The 3.0 measurement itself (four attack runs, 2026-08-06) is **not re-run** — item 1 is analysis of YAML and collector contracts only.

**Reason vocabulary**

- `condition-truly-doesnt-match` — the condition did not match for a reason that lies in the condition itself, not in the environment. Two sub-cases, kept apart by `status_rev7`: `structurally-dead` — unsatisfiable against what the collectors emit or what the kernel forwards (a dead axis / an impossible token), no environment can ever satisfy it; and `condition-changed-since-3.0` with decision `verify-after-fix` — the 3.0 condition named the wrong syscall number, which was satisfiable in principle but never the thing the rule meant, and waves 5–6 already replaced it.
- `no-input-data` — the condition is satisfiable on a live axis, but the four audited runs produced no matching event/value (scenario or environment absent).
- `duplicates-other-rule` — recorded in the `duplicate_of` column: another rule in the catalog carries an identical normalised condition.

**Decision vocabulary** (from plan.md item 1): `fix-condition` / `document-as-needing-environment` / `merge-with-duplicate`, plus `verify-after-fix` for a 3.0 condition that waves 5–6 proved wrong. **No rule is deleted or edited by item 1.**

## 2. Headline

- Rules re-annotated: **292** (Z1 120 + Z2 43 + Z3 5 + Z4 124), set-equal to the 3.0 Z sections.
- `condition-truly-doesnt-match`: **21** (19 structurally dead — 12 on `nr` + 3 on `op` + 4 on `proto` — plus 2 wrong-nr, the latter now fixed).
- `no-input-data`: **271** (well-formed, no matching input in the audited runs).
- Rules redundant with an identical-condition twin: **10**.
- Rules whose condition **changed in waves 5–6** (3.0 verdict stale): **29** — listed in §5.
- Rules left with reason “unknown why silent”: **0**.

Note on scope: the 292 is the **3.0-defined** set (Z1–Z4). This revision proves that set is complete and self-consistent; it does **not** re-run the stand, so for the 29 rules whose condition changed in waves 5–6 the 3.0 measurement is explicitly marked stale rather than silently reused.

| status_rev7 | count |
|---|---:|
| `silent-no-input` | 250 |
| `condition-changed-since-3.0` | 23 |
| `structurally-dead` | 19 |

The point of the revision: the 3.0 bucket “292 silent, condition never matched, reason = REVIEW” is gone. Every one of the 292 now carries a reason grounded in the current YAML and the collector contract, and the “unknown” count is zero.

## 3. Conditions that do not match for their own sake (`condition-truly-doesnt-match`)

19 rows are `structurally-dead`: no environment can satisfy them. The remaining 2 are the wrong-syscall-number rules waves 5–6 already corrected — listed here because the 3.0 silence was the condition's fault, not the environment's, but they are **not** structurally dead and carry `verify-after-fix`, not `fix-condition`.

| rule | ref | required dead token(s) | why it does not match | decision |
|---|---|---|---|---|
| `c2_icmp_large_payload` | `command-and-control.yaml:336` | `[1]` | collector emits only proto=6 (IPPROTO_TCP) — `bpf/network.bpf.c:124,136,226,241` | fix-condition |
| `c2_raw_socket_shell` | `command-and-control.yaml:24` | `[41]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `cis_5_2_1_privileged_container` | `cis-k8s.yaml:86` | `—` | syscall number was wrong in 3.0; corrected in waves 5–6 | verify-after-fix |
| `cis_5_2_5_privilege_escalation` | `cis-k8s.yaml:246` | `—` | syscall number was wrong in 3.0; corrected in waves 5–6 | verify-after-fix |
| `defense_evasion_journald_log_clear` | `credential-and-defense-gaps.yaml:60` | `[rmdir,truncate,unlink]` | collector emits only open/read/write/chmod — `bpf/common.h` FILE_OP_* | fix-condition |
| `evasion_auditd_stop` | `defense-evasion.yaml:166` | `[37,62,238]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `evasion_log_clear` | `defense-evasion.yaml:3` | `[rename,truncate,unlink]` | collector emits only open/read/write/chmod — `bpf/common.h` FILE_OP_* | fix-condition |
| `evasion_timestamp_modify` | `defense-evasion.yaml:28` | `[132,235,280]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `exfil_raw_socket_by_non_root` | `exfiltration-extended.yaml:175` | `[41]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `impact_fork_bomb_pattern` | `impact-gaps.yaml:61` | `[56,57]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `impact_mass_file_deletion_critical` | `impact-gaps.yaml:33` | `[rmdir,unlink]` | collector emits only open/read/write/chmod — `bpf/common.h` FILE_OP_* | fix-condition |
| `mitre_sandbox_detect_cpuid` | `mitre-additional.yaml:351` | `[135]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `netintr_gre_tunnel` | `network-intrusion.yaml:334` | `[47]` | collector emits only proto=6 (IPPROTO_TCP) — `bpf/network.bpf.c:124,136,226,241` | fix-condition |
| `netintr_icmp_outbound_large` | `network-intrusion.yaml:209` | `[1]` | collector emits only proto=6 (IPPROTO_TCP) — `bpf/network.bpf.c:124,136,226,241` | fix-condition |
| `netintr_raw_socket_connection` | `network-intrusion.yaml:322` | `[41,43,47,50,51,255]` | collector emits only proto=6 (IPPROTO_TCP) — `bpf/network.bpf.c:124,136,226,241` | fix-condition |
| `persist_systemd_wants_symlink` | `persistence-extended.yaml:40` | `[88]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `sigma_mprotect_exec_heap` | `sigma-linux.yaml:1475` | `[10]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `sigma_prctl_dumpable` | `sigma-linux.yaml:1339` | `[157]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `sigma_seccomp_filter_install` | `sigma-linux.yaml:1537` | `[317]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `sigma_world_writable_dir_created` | `sigma-linux.yaml:792` | `[83,258]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |
| `web_blind_sqli_heuristic` | `web-attacks-enhanced.yaml:78` | `[35,162,206]` | syscall number outside the in-kernel allowlist — `bpf/syscall.bpf.c:52` | fix-condition |

Three dead axes occur in this set. **`op`** (3 rules): every file event is emitted with `op ∈ {open, read, write, chmod}` (`bpf/common.h` `FILE_OP_OPEN/READ/WRITE/CHMOD`, rendered by `fileOpNames` in `internal/correlator/rules.go`; hooks in `internal/collector/fileaccess.go`). A rule that ANDs an `op` condition whose whole value set lies outside that set can never fire — the same limitation the repo already records for `sigma_log_deletion` (`rules/sigma-linux.yaml:385-388`, находка №234). The same defect also affects `ransomware_log_wipe` (`rules/ransomware.yaml:133`), which is outside the 292 and so outside this table.

**`proto`** (4 rules): `bpf/network.bpf.c` hardcodes `IPPROTO_TCP` (`6`) on every tcp_connect event (lines 124, 136, 226, 241) and no UDP/ICMP/GRE event type exists, so `proto` is only ever the string `"6"`; any `proto` condition whose values lie outside `{6}` (here ICMP/GRE/HOPOPT/ESP/AH/IPv6/…) is unsatisfiable.

**`nr`** (12 rules): the `nr` axis is **not** unconditionally live. `bpf/syscall.bpf.c:52` drops the event before the ring buffer unless `syscall_is_monitored()` finds the number in `syscall_filter_map`, which is programmed from `cfg.BPF.KernelFilter.MonitoredSyscalls` — 22 numbers in `config/config.yaml`, with `kernel_filter.enabled: true`. A rule whose whole numeric `nr` set lies outside that list can never receive an event, exactly like the `proto` rules above, and no attack scenario can change that. `ReferencedSyscalls()` could widen the list from the rules themselves, but `SetSyscallFilterUpdater` is not registered in `cmd/ebpf-guard/main.go`, so the configured list is what runs. The shorter `DefaultMonitoredSyscalls()` (19 numbers) used by the stand's `config-test.yaml` is a strict subset, so every rule counted here is dead under either resolution.

This axis was missed by the first cut of revision 7.0, which asserted `nr` was live, and it was also under-reported by the product's own startup audit: `UnreachableSyscallRules` tested `cond.Field != "nr"` literally, so the 12 rules below — every one written with the dotted `syscall.nr` alias that `normaliseFieldName` resolves — were invisible to it, as was the short `eq` operator. Both aliases are now normalised through `namesLiteralValues`, and the product's count rose from 9 to 17 catalog-wide. That is not new lost detection: these rules have been mute since they were written. The eight outside the 292 are recorded in `deploy/docker-test-setup/attacks/intentional-loss.txt`.

For all 19 the condition itself is the defect, so the recorded decision is `fix-condition` — *not* `document-as-needing-environment`, because the missing input can never exist. The fix is deliberately not applied in this wave: it changes detection semantics (`op: unlink|rmdir|truncate|rename → drop`, `proto: 1,47,… → drop or re-key`, `nr` → open the syscall in the allowlist and pay the noise, or re-key the rule) and needs the stand to verify, which is what the owner decision (plan item 8) reserves. **No condition is edited and no rule is deleted by this item.**

Budget check on the 3.0 → rev 7 boundary: the 3 `op`-dead rules are `file` rules, the 4 `proto`-dead rules are `tcp_connect`/Z2 rules and the 12 `nr`-dead rules are `syscall`/Z1 rules; the other 271 keep `no-input-data`. Rules that carry an unemitted token *alongside* a live one (e.g. `create` with `write`; see §5b) are **not** counted here, and neither are the 2 `verify-after-fix` rules whose dead condition was already replaced.

## 3b. Why the rest are `no-input-data` — the input axis per event type

3.0 established the fact of silence (four runs, attacker comms `curl`/`sqlmap`/`docker-proxy`); rev 7.0 supplies the *axis* the missing input had to arrive on. The axes below are live in the current collectors — so a rule that stayed silent is satisfiable-but-untested, not structurally dead (the rules lifted to §3 are the exception). Keyed by the rule's CURRENT event type: waves 5–6 moved two Z1 rules onto `file`, so a Z-keyed axis would describe the wrong collector for them.

| event_type | live input axis | evidence in code |
|---|---|---|
| syscall | `nr` **restricted to the in-kernel allowlist** (§3), plus `arg0..5`/`ret`/`comm`/`parent_comm`, and `proc.args` on execve/execveat only | `bpf/syscall.bpf.c:42-99`, `internal/collector/syscall.go:334-361` |
| tcp_connect | `dport`/`daddr`/`sport`/`saddr`/`family` (`proto` is always `6` — those rules are dead, §3) | `bpf/network.bpf.c:124-140`, `internal/correlator/rules.go:1573-1588` |
| net_close | `duration_sec` + `dport` | `internal/correlator/rules.go:1846-1858` |
| file | `filename`/`op`/`comm`/`directory`/`extension` (all four ops populate the path) | `bpf/fileaccess.bpf.c`, `internal/correlator/rules.go:1628-1660` |

A caveat this revision records rather than resolves: a `syscall` rule that constrains no `nr` at all (e.g. only `comm`/`parent_comm`) receives events only for the syscalls some *other* rule named or the baseline list carries — `ReferencedSyscalls()` documents the trade-off, and `ContextEmptySyscallRules` names the shape. Such a rule is satisfiable, so it stays `no-input-data`, but its input is narrower than its condition suggests.

The three 3.0 sections with a genuine **missing scenario**, stated as such: Z1 rules key on argv/syscall patterns the suite never executed (e.g. `pip install --index-url`, `env … sh`); Z2/Z3 rules key on ports/hosts/durations the suite never produced (no connection to `1080`/`4444`/metadata IPs, no session long enough to pass `duration_sec > 300…259200`); Z4 rules key on paths the suite never wrote (`/etc/sudoers.d/`, cron units, PAM config).

## 4. Redundant rules (`duplicate_of`)

| rule | ref | identical-condition twin(s) | decision |
|---|---|---|---|
| `appexploit_cri_socket_access` | `application-exploits.yaml:459` | `container_escape_crio_socket` | merge-with-duplicate |
| `appexploit_ssrf_gcp_metadata` | `application-exploits.yaml:329` | `cloud_ext_gcp_compute_metadata_access` | merge-with-duplicate |
| `cis_5_2_1_privileged_container` | `cis-k8s.yaml:86` | `container_escape_unshare_user,privesc_unshare_user_ns` | verify-after-fix |
| `cloud_ext_gcp_compute_metadata_access` | `cloud-attacks-extended.yaml:194` | `appexploit_ssrf_gcp_metadata` | merge-with-duplicate |
| `cloud_ext_k8s_etcd_access` | `cloud-attacks-extended.yaml:322` | `k8s_etcd_direct_access` | merge-with-duplicate |
| `owasp_web_shell_spawn` | `owasp-web.yaml:156` | `web_sql_injection_command` | merge-with-duplicate |
| `privesc_unshare_user_ns` | `privesc.yaml:324` | `cis_5_2_1_privileged_container,container_escape_unshare_user` | merge-with-duplicate |
| `proc_inject_memfd_create` | `process-injection.yaml:45` | `sigma_memfd_create_anonymous` | merge-with-duplicate |
| `sigma_memfd_create_anonymous` | `sigma-linux.yaml:1450` | `proc_inject_memfd_create` | merge-with-duplicate |
| `web_sql_injection_command` | `web-attacks-enhanced.yaml:59` | `owasp_web_shell_spawn` | merge-with-duplicate |

Both sides of every twin pair were `silent` in 3.0 as well, so duplication does **not** explain the silence — it is recorded as a redundancy decision, and the silence of each member is still annotated as `no-input-data`. Merging is a catalog change and is left to the owner decision (plan item 8); nothing is deleted here. The `reason_rev7` column is therefore never `duplicates-other-rule`: **no rule in the 292 duplicates a rule that actually fires**, which is what would make duplication a cause of silence rather than a maintenance note.

## 5. Conditions changed in waves 5–6 (3.0 verdict stale)

| rule | ref | 3.0 → rev 7 event_type | decision |
|---|---|---|---|
| `c2_ingress_piped_to_shell` | `collection-and-evasion-gaps.yaml:123` | syscall | document-as-needing-environment |
| `cis_5_2_1_privileged_container` | `cis-k8s.yaml:86` | syscall | verify-after-fix |
| `cis_5_2_5_privilege_escalation` | `cis-k8s.yaml:246` | syscall | verify-after-fix |
| `drift_dangerous_syscall` | `drift-rules.yaml:260` | syscall | document-as-needing-environment |
| `evasion_chmod_sensitive` | `defense-evasion.yaml:73` | syscall → file | document-as-needing-environment |
| `evasion_iptables_flush` | `defense-evasion.yaml:239` | syscall | document-as-needing-environment |
| `exfil_archive_to_network_pipe` | `exfiltration-extended.yaml:305` | syscall | document-as-needing-environment |
| `initial_driveby_browser_download_exec` | `initial-access.yaml:233` | syscall | document-as-needing-environment |
| `initial_email_link_download_exec` | `initial-access.yaml:265` | syscall | document-as-needing-environment |
| `initial_office_macro_exec` | `initial-access.yaml:49` | syscall | document-as-needing-environment |
| `mitre_sandbox_detect_cpuid` | `mitre-additional.yaml:351` | syscall | fix-condition |
| `owasp_web_shell_spawn` | `owasp-web.yaml:156` | syscall | merge-with-duplicate |
| `privesc_setns_syscall` | `privesc.yaml:160` | syscall | document-as-needing-environment |
| `proc_inject_fexecve` | `process-injection.yaml:80` | syscall | document-as-needing-environment |
| `proc_inject_ptrace` | `process-injection.yaml:15` | syscall | document-as-needing-environment |
| `sigma_chmod_executable_tmp` | `sigma-linux.yaml:248` | syscall → file | document-as-needing-environment |
| `sigma_iptables_flush` | `sigma-linux.yaml:1571` | syscall | document-as-needing-environment |
| `sigma_mprotect_exec_heap` | `sigma-linux.yaml:1475` | syscall | fix-condition |
| `sigma_prctl_dumpable` | `sigma-linux.yaml:1339` | syscall | fix-condition |
| `sigma_process_vm_readv` | `sigma-linux.yaml:1497` | syscall | document-as-needing-environment |
| `sigma_process_vm_writev` | `sigma-linux.yaml:1516` | syscall | document-as-needing-environment |
| `sigma_ptrace_attach` | `sigma-linux.yaml:1424` | syscall | document-as-needing-environment |
| `sigma_seccomp_filter_install` | `sigma-linux.yaml:1537` | syscall | fix-condition |
| `sigma_setuid_syscall` | `sigma-linux.yaml:1318` | syscall | document-as-needing-environment |
| `sigma_shell_from_unexpected_parent` | `sigma-linux.yaml:10` | syscall | document-as-needing-environment |
| `sigma_web_server_shell_spawn` | `sigma-linux.yaml:1726` | syscall | document-as-needing-environment |
| `sigma_world_writable_dir_created` | `sigma-linux.yaml:792` | syscall | fix-condition |
| `web_blind_sqli_heuristic` | `web-attacks-enhanced.yaml:78` | syscall | fix-condition |
| `web_sql_injection_command` | `web-attacks-enhanced.yaml:59` | syscall | merge-with-duplicate |

These 3.0-silent rules no longer have the condition the 3.0 run measured, so the 3.0 verdict cannot be carried forward. Two were corrected for a **wrong syscall number**: `cis_5_2_1_privileged_container` nr `['160']`→`['272']` (setrlimit→unshare) and `cis_5_2_5_privilege_escalation` nr `['82', '105']`→`['105', '106']` (drops rename, adds setgid). `evasion_chmod_sensitive` and `sigma_chmod_executable_tmp` were restructured syscall→file. The remaining 25 were narrowed — their leaf set differs, which is what `changed_since_3_0` measures. A rule that gained ONLY an `exceptions:` block is deliberately **not** in this set: `exceptions` can only suppress, never create a match, so it cannot have un-silenced a rule — see §5c.

## 5b. Systemic note — the `create` op token

**28** rules in the 292 carry `create` among their `file.op` values. The collector never emits `create` (creation appears as `open`), so the token is dead weight; every one of these rules also lists `write`, which is why none is `structurally-dead`. They are recorded, not edited: the fix would be `create → open` (part of each rule's `fix-condition` debt), a detection-design change that needs the stand to verify.

## 5c. Systemic note — the `exceptions` axis

**7** of the 292 differ from 3.0 by an added `exceptions:` block. `exceptions` can only suppress a match, never create one, so such a rule cannot have been un-silenced by the change and stays `silent-no-input`; that is why they are excluded from the 29-rule stale-verdict set. Lesson for future revisions: a condition-hash comparison that ignores `exceptions` mislabels these as unchanged.

## 6. Full table (292 rows)

Grouped by reason, then by Z-section. Machine-readable twin: [`rules-audit-2026-09-27.csv`](rules-audit-2026-09-27.csv).

### 6.1 `condition-truly-doesnt-match` (21)

| rule | Z | event_type | current ref | changed | status | decision | condition (current YAML) |
|---|---|---|---|---|---|---|---|
| `c2_raw_socket_shell` | Z1 | syscall | `command-and-control.yaml:24` | no | structurally-dead | fix-condition | proc.comm in [bash,sh,zsh,python3…] AND syscall.nr equals [41] |
| `cis_5_2_1_privileged_container` | Z1 | syscall | `cis-k8s.yaml:86` | yes | condition-changed-since-3.0 | verify-after-fix | nr in [272] |
| `cis_5_2_5_privilege_escalation` | Z1 | syscall | `cis-k8s.yaml:246` | yes | condition-changed-since-3.0 | verify-after-fix | nr in [105,106] AND comm not_in [sshd,su,sudo,cron…] |
| `evasion_auditd_stop` | Z1 | syscall | `defense-evasion.yaml:166` | no | structurally-dead | fix-condition | syscall.nr in [62,37,238] AND proc.comm in [bash,sh,zsh,python3…] |
| `evasion_timestamp_modify` | Z1 | syscall | `defense-evasion.yaml:28` | no | structurally-dead | fix-condition | syscall.nr in [132,280,235] AND proc.comm not_in [touch,rsync,git,tar…] |
| `exfil_raw_socket_by_non_root` | Z1 | syscall | `exfiltration-extended.yaml:175` | no | structurally-dead | fix-condition | syscall.nr equals [41] AND uid not_in [0] AND proc.comm not_in [ping,traceroute,tracepath,mtr…] |
| `impact_fork_bomb_pattern` | Z1 | syscall | `impact-gaps.yaml:61` | no | structurally-dead | fix-condition | syscall.nr in [56,57] AND uid not_in [0] |
| `mitre_sandbox_detect_cpuid` | Z1 | syscall | `mitre-additional.yaml:351` | yes | structurally-dead | fix-condition | nr in [135] AND arg0 in [4113,4114] |
| `persist_systemd_wants_symlink` | Z1 | syscall | `persistence-extended.yaml:40` | no | structurally-dead | fix-condition | syscall.nr in [88] AND proc.comm not_in [systemctl,dpkg,rpm,apt…] |
| `sigma_mprotect_exec_heap` | Z1 | syscall | `sigma-linux.yaml:1475` | yes | structurally-dead | fix-condition | nr in [10] AND arg2 in [4,5,6,7] |
| `sigma_prctl_dumpable` | Z1 | syscall | `sigma-linux.yaml:1339` | yes | structurally-dead | fix-condition | nr in [157] AND arg0 in [4] AND arg1 eq [0] |
| `sigma_seccomp_filter_install` | Z1 | syscall | `sigma-linux.yaml:1537` | yes | structurally-dead | fix-condition | nr in [317] AND comm not_in [runc,containerd-shim,containerd-shim-runc-v2,dockerd…] |
| `sigma_world_writable_dir_created` | Z1 | syscall | `sigma-linux.yaml:792` | yes | structurally-dead | fix-condition | (nr eq [83] AND arg1 eq [511]) OR (nr eq [258] AND arg2 eq [511]) |
| `web_blind_sqli_heuristic` | Z1 | syscall | `web-attacks-enhanced.yaml:78` | yes | structurally-dead | fix-condition | nr in [35,206,162] AND parent_comm in [nginx,apache2,httpd,php-fpm…] |
| `c2_icmp_large_payload` | Z2 | tcp_connect | `command-and-control.yaml:336` | no | structurally-dead | fix-condition | network.proto equals [1] AND network.dport gt [200] |
| `netintr_gre_tunnel` | Z2 | tcp_connect | `network-intrusion.yaml:334` | no | structurally-dead | fix-condition | proto in [47] |
| `netintr_icmp_outbound_large` | Z2 | tcp_connect | `network-intrusion.yaml:209` | no | structurally-dead | fix-condition | proto in [1] |
| `netintr_raw_socket_connection` | Z2 | tcp_connect | `network-intrusion.yaml:322` | no | structurally-dead | fix-condition | proto in [255,41,43,47…] |
| `defense_evasion_journald_log_clear` | Z4 | file | `credential-and-defense-gaps.yaml:60` | no | structurally-dead | fix-condition | file.path prefix [/var/log/] AND file.op in [unlink,rmdir,truncate] AND proc.comm not_in [logrotate,logrotate.d,journalctl,rsyslogd…] |
| `evasion_log_clear` | Z4 | file | `defense-evasion.yaml:3` | no | structurally-dead | fix-condition | file.path prefix [/var/log/] AND file.op in [unlink,truncate,rename] AND proc.comm not_in [logrotate,newsyslog,journald,rsyslog…] |
| `impact_mass_file_deletion_critical` | Z4 | file | `impact-gaps.yaml:33` | no | structurally-dead | fix-condition | file.path prefix [/etc/,/var/log/,/boot/,/lib/modules/…] AND file.op in [unlink,rmdir] |

### 6.2 `no-input-data` (271)

| rule | Z | event_type | current ref | changed | status | decision | condition (current YAML) |
|---|---|---|---|---|---|---|---|
| `appexploit_pip_install_malicious` | Z1 | syscall | `application-exploits.yaml:411` | no | silent-no-input | document-as-needing-environment | proc.args regex [pip.*install.*--index-url,pip.*install.*--extra-index-url,pip.*install.*/tmp/,pip.*install.*/dev/shm/] |
| `appexploit_shellshock_pattern` | Z1 | syscall | `application-exploits.yaml:92` | no | silent-no-input | document-as-needing-environment | proc.args regex [\(\)\s*\{\s*:;\},\(\)\s*\{\s*ignored;\},bash -c.*\(\)\s*\{] |
| `appexploit_sqli_exec_xp` | Z1 | syscall | `application-exploits.yaml:177` | no | silent-no-input | document-as-needing-environment | proc.args regex [(?i)xp_cmdshell,(?i)exec.*master\.dbo,(?i)sp_configure.*xp_cmdshell] |
| `appexploit_sqli_outfile` | Z1 | syscall | `application-exploits.yaml:162` | no | silent-no-input | document-as-needing-environment | proc.args regex [(?i)SELECT.*INTO.*OUTFILE,(?i)SELECT.*INTO.*DUMPFILE,(?i)LOAD_FILE.*\(] |
| `appexploit_ssti_pattern` | Z1 | syscall | `application-exploits.yaml:196` | no | silent-no-input | document-as-needing-environment | proc.args regex [\{\{.*\.__class__.*\.__mro__,\$\{T\(java\.lang\.Runtime\),\$\{.*Runtime\.getRuntime\(\),#set.*ClassLoader] |
| `c2_ingress_piped_to_shell` | Z1 | syscall | `collection-and-evasion-gaps.yaml:123` | yes | condition-changed-since-3.0 | document-as-needing-environment | proc.comm in [bash,sh,zsh,dash…] AND syscall.nr equals [59] AND proc.parent_comm not_in [sshd,cron,systemd,run-parts…] AND proc.args regex [^(/usr/local/bin/… |
| `c2_remote_access_tool` | Z1 | syscall | `command-and-control.yaml:312` | no | silent-no-input | document-as-needing-environment | proc.comm in [ngrok,frp,frpc,frps…] AND syscall.nr equals [59] |
| `cis_5_1_1_cluster_admin_usage` | Z1 | syscall | `cis-k8s.yaml:6` | no | silent-no-input | document-as-needing-environment | comm regex [kubectl,helm] |
| `drift_dangerous_syscall` | Z1 | syscall | `drift-rules.yaml:260` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [ptrace,mount,umount2,unshare…] AND comm not_in [runc,containerd-shim,containerd-shim-runc-v2,dockerd…] |
| `evasion_base64_shell_decode` | Z1 | syscall | `defense-evasion.yaml:188` | no | silent-no-input | document-as-needing-environment | proc.comm in [base64,openssl,xxd,od…] AND syscall.nr equals [59] |
| `evasion_chmod_sensitive` | Z1 | file | `defense-evasion.yaml:73` | yes | condition-changed-since-3.0 | document-as-needing-environment | file.op eq [chmod] AND file.path prefix [/bin/,/sbin/,/usr/bin/,/usr/sbin/…] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `evasion_iptables_flush` | Z1 | syscall | `defense-evasion.yaml:239` | yes | condition-changed-since-3.0 | document-as-needing-environment | proc.comm in [iptables,ip6tables,nft,firewall-cmd…] AND syscall.nr equals [59] AND proc.args regex [(^\|\s)(-F\|--flush\|-X\|--delete-chain)(\s\|$),flush rul… |
| `evasion_self_delete` | Z1 | syscall | `defense-evasion.yaml:209` | no | silent-no-input | document-as-needing-environment | syscall.nr in [87,263] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `exec_from_tmp` | Z1 | syscall | `sigma-linux.yaml:359` | no | silent-no-input | document-as-needing-environment | proc.args prefix [/tmp/,/dev/shm/,/var/tmp/] |
| `execution_dbus_activation_attack` | Z1 | syscall | `credential-and-defense-gaps.yaml:86` | no | silent-no-input | document-as-needing-environment | proc.comm in [dbus-send,gdbus,dbus-monitor,dbus-launch] AND syscall.nr equals [59] |
| `exfil_archive_to_network_pipe` | Z1 | syscall | `exfiltration-extended.yaml:305` | yes | condition-changed-since-3.0 | document-as-needing-environment | proc.comm in [nc,ncat,netcat,curl…] AND syscall.nr equals [59] AND proc.parent_comm in [tar,zip,gzip,gunzip…] |
| `exfil_cloud_sync_tool` | Z1 | syscall | `exfiltration-extended.yaml:341` | no | silent-no-input | document-as-needing-environment | proc.comm in [rclone,s3cmd,s3,gsutil…] AND syscall.nr equals [59] AND uid not_in [0] |
| `impact_systemd_service_disabled` | Z1 | syscall | `impact-gaps.yaml:5` | no | silent-no-input | document-as-needing-environment | proc.comm in [systemctl,service] AND syscall.nr equals [59] AND uid equals [0] |
| `initial_driveby_browser_download_exec` | Z1 | syscall | `initial-access.yaml:233` | yes | condition-changed-since-3.0 | document-as-needing-environment | proc.comm in [bash,sh,zsh,python3…] AND syscall.nr equals [59] AND proc.parent_comm in [chrome,chromium,chromium-browser,google-chrome…] |
| `initial_email_link_download_exec` | Z1 | syscall | `initial-access.yaml:265` | yes | condition-changed-since-3.0 | document-as-needing-environment | proc.comm in [bash,sh,zsh,python3…] AND syscall.nr equals [59] AND proc.parent_comm in [thunderbird,evolution,mutt,neomutt…] |
| `initial_office_macro_exec` | Z1 | syscall | `initial-access.yaml:49` | yes | condition-changed-since-3.0 | document-as-needing-environment | proc.comm in [bash,sh,zsh,python3…] AND syscall.nr equals [59] AND proc.parent_comm in [soffice,soffice.bin,libreoffice,acroread…] |
| `initial_vpn_unexpected_access` | Z1 | syscall | `initial-access.yaml:167` | no | silent-no-input | document-as-needing-environment | proc.comm in [openvpn,wireguard,wg,tor…] AND syscall.nr equals [59] |
| `integrity_proc_self_exe_exec` | Z1 | syscall | `runtime-integrity.yaml:201` | no | silent-no-input | document-as-needing-environment | syscall.nr in [319,279] |
| `lateral_netcat_socat_pivot` | Z1 | syscall | `lateral-movement.yaml:150` | no | silent-no-input | document-as-needing-environment | proc.comm in [nc,ncat,netcat,socat…] AND syscall.nr equals [59] |
| `lateral_ssh_from_container` | Z1 | syscall | `lateral-movement.yaml:3` | no | silent-no-input | document-as-needing-environment | proc.comm in [ssh,sshpass,autossh,plink…] AND syscall.nr equals [59] |
| `lateral_ssh_keygen_new_key` | Z1 | syscall | `lateral-movement.yaml:24` | no | silent-no-input | document-as-needing-environment | proc.comm equals [ssh-keygen] AND syscall.nr equals [59] |
| `lolbin_apt_pre_invoke` | Z1 | syscall | `living-off-the-land.yaml:119` | no | silent-no-input | document-as-needing-environment | proc.args regex [apt.*Pre-Invoke.*sh,apt.*Post-Invoke.*sh,apt.*-o.*Pre-Invoke,apt-get.*-o.*APT::Update] |
| `lolbin_bash_dev_tcp` | Z1 | syscall | `living-off-the-land.yaml:445` | no | silent-no-input | document-as-needing-environment | proc.args regex [bash.*dev/tcp/,bash.*\$\{.*dev/tcp,exec.*>/dev/tcp/,0</dev/tcp/] |
| `lolbin_bash_dev_udp` | Z1 | syscall | `living-off-the-land.yaml:461` | no | silent-no-input | document-as-needing-environment | proc.args regex [bash.*dev/udp/,exec.*>/dev/udp/,0</dev/udp/] |
| `lolbin_bash_interactive_shell` | Z1 | syscall | `living-off-the-land.yaml:550` | no | silent-no-input | document-as-needing-environment | proc.args regex [bash\s+-i\b,bash\s+--interactive\b,/bin/bash\s+-i\b,/usr/bin/bash\s+-i\b] |
| `lolbin_curl_data_exfil` | Z1 | syscall | `living-off-the-land.yaml:410` | no | silent-no-input | document-as-needing-environment | proc.args regex [curl.*--data.*@/,curl.*-d.*@/etc/,curl.*-F.*@/root/,curl.*--data-binary.*@/] |
| `lolbin_dpkg_exec` | Z1 | syscall | `living-off-the-land.yaml:105` | no | silent-no-input | document-as-needing-environment | proc.args regex [dpkg.*--force-script,dpkg-deb.*--build.*--exec] |
| `lolbin_find_sensitive_recon` | Z1 | syscall | `living-off-the-land.yaml:573` | no | silent-no-input | document-as-needing-environment | proc.args regex [find.*-name.*\.key,find.*-name.*\.pem,find.*-name.*\.p12,find.*-name.*\.pfx…] |
| `lolbin_gdb_exec` | Z1 | syscall | `living-off-the-land.yaml:57` | no | silent-no-input | document-as-needing-environment | proc.args regex [gdb.*--batch.*--ex.*call system,gdb.*-batch.*-ex.*call,gdb.*-ex.*call system,gdb.*--eval-command] |
| `lolbin_git_clone_to_tmp` | Z1 | syscall | `living-off-the-land.yaml:326` | no | silent-no-input | document-as-needing-environment | proc.args regex [git clone.*/tmp/,git clone.*/dev/shm/,git clone.*/var/tmp/] |
| `lolbin_ld_audit_set` | Z1 | syscall | `living-off-the-land.yaml:376` | no | silent-no-input | document-as-needing-environment | proc.args regex [LD_AUDIT=.*\.so,export LD_AUDIT=] |
| `lolbin_less_exec` | Z1 | syscall | `living-off-the-land.yaml:168` | no | silent-no-input | document-as-needing-environment | proc.args regex [less.*-e.*sh,less.*VISUAL.*sh,less.*LESSSECURE] |
| `lolbin_lua_exec` | Z1 | syscall | `living-off-the-land.yaml:216` | no | silent-no-input | document-as-needing-environment | proc.args regex [lua.*os\.execute,lua.*io\.popen,lua -e.*os\.execute] |
| `lolbin_make_exec` | Z1 | syscall | `living-off-the-land.yaml:135` | no | silent-no-input | document-as-needing-environment | proc.args regex [make.*--eval.*run,make.*MAKEFLAGS.*-n,make.*-C /tmp,make.*-C /dev/shm] |
| `lolbin_nmap_script_exec` | Z1 | syscall | `living-off-the-land.yaml:27` | no | silent-no-input | document-as-needing-environment | proc.args regex [nmap.*--script.*exec,nmap.*--script.*shell,nmap.*-e.*,nmap.*--script-args.*cmd] |
| `lolbin_node_exec` | Z1 | syscall | `living-off-the-land.yaml:231` | no | silent-no-input | document-as-needing-environment | proc.args regex [node.*child_process.*exec,node.*require.*child_process,node -e.*spawn.*sh,nodejs -e.*exec] |
| `lolbin_path_hijack_indicator` | Z1 | syscall | `living-off-the-land.yaml:360` | no | silent-no-input | document-as-needing-environment | proc.args regex [PATH=/tmp:,PATH=/dev/shm:,PATH=/var/tmp:,export PATH=/tmp] |
| `lolbin_perl_socket_shell` | Z1 | syscall | `living-off-the-land.yaml:492` | no | silent-no-input | document-as-needing-environment | proc.args regex [perl.*socket.*SOCK_STREAM.*exec.*sh,perl.*IO::Socket.*exec.*sh,perl.*use POSIX.*dup2.*exec.*sh] |
| `lolbin_php_exec_oneliner` | Z1 | syscall | `living-off-the-land.yaml:247` | no | silent-no-input | document-as-needing-environment | proc.args regex [php -r.*system\(,php -r.*exec\(,php -r.*shell_exec\(,php -r.*passthru\(…] |
| `lolbin_pip_download_to_tmp` | Z1 | syscall | `living-off-the-land.yaml:341` | no | silent-no-input | document-as-needing-environment | proc.args regex [pip.*download.*/tmp/,pip.*download.*/dev/shm/,pip3.*download.*/tmp/] |
| `lolbin_python_socket_shell` | Z1 | syscall | `living-off-the-land.yaml:476` | no | silent-no-input | document-as-needing-environment | proc.args regex [python.*import socket.*os.*dup2,python.*socket\.connect.*dup2,python.*\bos\.dup2\(s\.fileno,python.*\bsubprocess\.call.*\[.*sh] |
| `lolbin_rsync_staging` | Z1 | syscall | `living-off-the-land.yaml:298` | no | silent-no-input | document-as-needing-environment | proc.args regex [rsync.*[a-z]+@[^:]+:.*/tmp/,rsync.*[a-z]+@[^:]+:.*/dev/shm/] |
| `lolbin_ruby_socket_shell` | Z1 | syscall | `living-off-the-land.yaml:507` | no | silent-no-input | document-as-needing-environment | proc.args regex [ruby.*TCPSocket.*exec.*sh,ruby.*Socket.*new.*exec,ruby.*require.*socket.*spawn.*sh] |
| `lolbin_scp_download_to_tmp` | Z1 | syscall | `living-off-the-land.yaml:283` | no | silent-no-input | document-as-needing-environment | proc.args regex [scp.*:/tmp/,scp.*:/dev/shm/,scp.*:/var/tmp/] |
| `lolbin_sftp_staging` | Z1 | syscall | `living-off-the-land.yaml:312` | no | silent-no-input | document-as-needing-environment | proc.args regex [sftp.*-b.*get ,sftp.*-b.*put.*\.sh] |
| `lolbin_socat_shell` | Z1 | syscall | `living-off-the-land.yaml:10` | no | silent-no-input | document-as-needing-environment | proc.args regex [socat.*EXEC.*sh,socat.*EXEC.*bash,socat.*TCP.*EXEC,socat.*PTY.*EXEC…] |
| `lolbin_tar_exec` | Z1 | syscall | `living-off-the-land.yaml:183` | no | silent-no-input | document-as-needing-environment | proc.args regex [tar.*--to-command.*sh,tar.*--checkpoint-action=exec,tar.*--to-command=/bin/sh] |
| `lolbin_tclsh_exec` | Z1 | syscall | `living-off-the-land.yaml:73` | no | silent-no-input | document-as-needing-environment | proc.args regex [tclsh.*exec\s+sh,tclsh.*exec\s+bash,expect.*spawn.*sh,expect.*spawn.*bash…] |
| `lolbin_tcpdump_write` | Z1 | syscall | `living-off-the-land.yaml:264` | no | silent-no-input | document-as-needing-environment | proc.args regex [tcpdump.*-w /tmp/,tcpdump.*-w /dev/shm/,tcpdump.*-w /var/tmp/] |
| `lolbin_vim_exec` | Z1 | syscall | `living-off-the-land.yaml:151` | no | silent-no-input | document-as-needing-environment | proc.args regex [vim.*-c.*:!.*sh,vim.*-c.*:!/bin/sh,ex.*-c.*:!.*sh,vim.*-c.*:set.*shell…] |
| `lolbin_wget_download_tmp` | Z1 | syscall | `living-off-the-land.yaml:526` | no | silent-no-input | document-as-needing-environment | proc.args regex [wget.*-O\s*/tmp/,wget.*-O\s*/dev/shm/,wget.*-O\s*/var/tmp/,wget.*--output-document[= ]/tmp/…] |
| `lolbin_wget_post_exfil` | Z1 | syscall | `living-off-the-land.yaml:426` | no | silent-no-input | document-as-needing-environment | proc.args regex [wget.*--post-file=/,wget.*--post-file=/etc/,wget.*--post-file=/root/] |
| `lolbin_zip_exec` | Z1 | syscall | `living-off-the-land.yaml:198` | no | silent-no-input | document-as-needing-environment | proc.args regex [zip.*-T.*--unzip-command,unzip.*-p.*\\|.*sh] |
| `mitre_obfusc_base64_payload_large` | Z1 | syscall | `mitre-additional.yaml:10` | no | silent-no-input | document-as-needing-environment | proc.args regex [echo [A-Za-z0-9+/]{100,}={0,2}\s*\\|,printf [A-Za-z0-9+/]{100,}={0,2}\s*\\|] |
| `mitre_obfusc_char_concatenation` | Z1 | syscall | `mitre-additional.yaml:58` | no | silent-no-input | document-as-needing-environment | proc.args regex [\$\([[:space:]]*echo[[:space:]]+.*\$IFS.*\),eval.*\$\(.*tr.*\),\{echo,.*\},\$\{IFS\}] |
| `mitre_obfusc_gzip_payload` | Z1 | syscall | `mitre-additional.yaml:40` | no | silent-no-input | document-as-needing-environment | proc.args regex [echo.*\\|.*base64.*\\|.*gzip,echo.*\\|.*base64.*\\|.*gunzip,gzip.*\\|.*base64.*\\|.*sh,zcat.*\\|.*sh…] |
| `mitre_obfusc_hex_encoded_exec` | Z1 | syscall | `mitre-additional.yaml:24` | no | silent-no-input | document-as-needing-environment | proc.args regex [xxd.*\\|.*sh,xxd -r.*\\|,printf.*\\x[0-9a-f]{2}.*\\|.*sh,\$'\\x[0-9a-f][0-9a-f]] |
| `mitre_systemd_transient_timer` | Z1 | syscall | `mitre-additional.yaml:663` | no | silent-no-input | document-as-needing-environment | proc.args regex [systemd-run.*--on-active,systemd-run.*--on-calendar,systemd-run.*--timer,systemd-run.*--on-boot] |
| `mitre_vpn_service_started` | Z1 | syscall | `mitre-additional.yaml:128` | no | silent-no-input | document-as-needing-environment | proc.args regex [openvpn.*--config,wg-quick up,wg set.*peer] |
| `owasp_web_shell_spawn` | Z1 | syscall | `owasp-web.yaml:156` | yes | condition-changed-since-3.0 | merge-with-duplicate | nr in [59,322,545] AND parent_comm in [nginx,apache2,httpd,php-fpm…] |
| `persistence_efi_boot_entry_modified` | Z1 | syscall | `collection-and-evasion-gaps.yaml:100` | no | silent-no-input | document-as-needing-environment | proc.comm in [efibootmgr,bcfg] AND syscall.nr equals [59] |
| `privesc_setns_syscall` | Z1 | syscall | `privesc.yaml:160` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [308] AND comm not_in [nsenter] |
| `privesc_unshare_user_ns` | Z1 | syscall | `privesc.yaml:324` | no | silent-no-input | merge-with-duplicate | nr in [272] |
| `proc_inject_fexecve` | Z1 | syscall | `process-injection.yaml:80` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [322] AND arg4 in [4096] |
| `proc_inject_memfd_create` | Z1 | syscall | `process-injection.yaml:45` | no | silent-no-input | merge-with-duplicate | nr in [319] |
| `proc_inject_ptrace` | Z1 | syscall | `process-injection.yaml:15` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [101] AND comm not_in [gdb,strace,perf,ltrace…] |
| `ptrace_attach` | Z1 | syscall | `process-injection.yaml:227` | no | silent-no-input | document-as-needing-environment | nr in [101] AND arg0 in [16] AND proc.comm not_in [gdb,strace,ltrace,perf…] |
| `recon_active_connections` | Z1 | syscall | `reconnaissance.yaml:47` | no | silent-no-input | document-as-needing-environment | proc.comm in [netstat,ss,lsof,nmap…] AND syscall.nr equals [59] |
| `recon_network_config` | Z1 | syscall | `reconnaissance.yaml:26` | no | silent-no-input | document-as-needing-environment | proc.comm in [ifconfig,ip,netstat,ss…] AND syscall.nr equals [59] |
| `recon_port_scan_outbound` | Z1 | syscall | `reconnaissance.yaml:179` | no | silent-no-input | document-as-needing-environment | proc.comm in [nmap,masscan,zmap,rustscan…] AND syscall.nr equals [59] |
| `recon_process_enum` | Z1 | syscall | `reconnaissance.yaml:135` | no | silent-no-input | document-as-needing-environment | proc.comm in [ps,pstree,top,htop…] AND syscall.nr equals [59] |
| `recon_security_tools_enum` | Z1 | syscall | `reconnaissance.yaml:157` | no | silent-no-input | document-as-needing-environment | proc.comm in [find,which,whereis,locate…] AND syscall.nr equals [59] |
| `recon_system_info` | Z1 | syscall | `reconnaissance.yaml:3` | no | silent-no-input | document-as-needing-environment | proc.comm in [uname,hostname,hostnamectl,dmidecode…] AND syscall.nr equals [59] |
| `recon_user_enum` | Z1 | syscall | `reconnaissance.yaml:69` | no | silent-no-input | document-as-needing-environment | proc.comm in [id,whoami,who,w…] AND syscall.nr equals [59] |
| `sigma_auditd_stopped` | Z1 | syscall | `sigma-linux.yaml:1598` | no | silent-no-input | document-as-needing-environment | proc.args regex [systemctl.*stop.*auditd,systemctl.*disable.*auditd,service.*auditd.*stop,auditctl.*-e 0] |
| `sigma_base64_execution_shell` | Z1 | syscall | `sigma-linux.yaml:59` | no | silent-no-input | document-as-needing-environment | proc.args regex [base64 -d,base64 --decode,\\|\s*base64,echo .* \\| bash] |
| `sigma_chmod_executable_tmp` | Z1 | file | `sigma-linux.yaml:248` | yes | condition-changed-since-3.0 | document-as-needing-environment | file.op eq [chmod] AND file.path prefix [/tmp/,/var/tmp/,/dev/shm/,/run/shm/] |
| `sigma_iptables_flush` | Z1 | syscall | `sigma-linux.yaml:1571` | yes | condition-changed-since-3.0 | document-as-needing-environment | proc.args regex [ip6?tables[^;\|&]*(^\|\s)(-F\|--flush)(\s\|$),ip6?tables[^;\|&]*(^\|\s)(-X\|--delete-chain)(\s\|$),ufw disable,systemctl stop firewalld…] |
| `sigma_lolbin_awk_shell` | Z1 | syscall | `sigma-linux.yaml:724` | no | silent-no-input | document-as-needing-environment | proc.args regex [awk.*system\(,awk.*BEGIN.*system,gawk.*system\(] |
| `sigma_lolbin_dd_write` | Z1 | syscall | `sigma-linux.yaml:769` | no | silent-no-input | document-as-needing-environment | proc.args regex [dd.*of=/dev/[sh]d,dd.*of=/dev/nvme,dd.*if=/dev/urandom.*of=,dd.*conv=notrunc…] |
| `sigma_lolbin_env_execution` | Z1 | syscall | `sigma-linux.yaml:755` | no | silent-no-input | document-as-needing-environment | proc.args regex [^env .*(sh\|bash\|python\|perl\|ruby\|node),env\s+-i\s+] |
| `sigma_lolbin_find_exec` | Z1 | syscall | `sigma-linux.yaml:739` | no | silent-no-input | document-as-needing-environment | proc.args regex [find.*-exec.*sh.*,find.*-exec.*bash.*,find.*-exec.*python.*,find.*-exec.*perl.*] |
| `sigma_lolbin_openssl_connect` | Z1 | syscall | `sigma-linux.yaml:710` | no | silent-no-input | document-as-needing-environment | proc.args regex [openssl.*s_client.*-connect,openssl.*s_server] |
| `sigma_lolbin_python_download` | Z1 | syscall | `sigma-linux.yaml:694` | no | silent-no-input | document-as-needing-environment | proc.args regex [python.*urllib.*urlretrieve,python.*urllib.*urlopen,python.*requests\.get,python.*http\.client] |
| `sigma_masquerade_kernel_thread` | Z1 | syscall | `sigma-linux.yaml:269` | no | silent-no-input | document-as-needing-environment | comm regex [^\[.*\]$] |
| `sigma_memfd_create_anonymous` | Z1 | syscall | `sigma-linux.yaml:1450` | no | silent-no-input | merge-with-duplicate | nr in [319] |
| `sigma_perl_shell_execution` | Z1 | syscall | `sigma-linux.yaml:109` | no | silent-no-input | document-as-needing-environment | proc.args regex [perl.*system\(,perl.*exec\(,perl -e.*\$_,perl.*\\|.*sh] |
| `sigma_process_vm_readv` | Z1 | syscall | `sigma-linux.yaml:1497` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [310] AND comm not_in [gdb,gcore,criu] |
| `sigma_process_vm_writev` | Z1 | syscall | `sigma-linux.yaml:1516` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [311] AND comm not_in [gdb,criu] |
| `sigma_ptrace_attach` | Z1 | syscall | `sigma-linux.yaml:1424` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [101] AND arg0 in [16,16902] |
| `sigma_python_exec_shell` | Z1 | syscall | `sigma-linux.yaml:93` | no | silent-no-input | document-as-needing-environment | proc.args regex [python.*os\.system,python.*subprocess,python.*pty\.spawn,python.*import os.*exec] |
| `sigma_ruby_shell_execution` | Z1 | syscall | `sigma-linux.yaml:125` | no | silent-no-input | document-as-needing-environment | proc.args regex [ruby.*exec\(,ruby.*system\(,ruby -e.*Kernel\.exec,ruby.*IO\.popen] |
| `sigma_script_dropper_via_curl` | Z1 | syscall | `sigma-linux.yaml:75` | no | silent-no-input | document-as-needing-environment | proc.args regex [curl.*\\|.*sh,curl.*\\|.*bash,wget.*\\|.*sh,wget.*\\|.*bash…] |
| `sigma_setuid_syscall` | Z1 | syscall | `sigma-linux.yaml:1318` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [105,106,113,114…] AND comm not_in [sshd,su,sudo,cron…] |
| `sigma_shell_from_unexpected_parent` | Z1 | syscall | `sigma-linux.yaml:10` | yes | condition-changed-since-3.0 | document-as-needing-environment | nr in [59] AND comm regex [^sh$,^bash$,^dash$,^zsh$…] AND parent_comm not_in [sshd,cron,systemd,run-parts…] |
| `sigma_web_server_shell_spawn` | Z1 | syscall | `sigma-linux.yaml:1726` | yes | condition-changed-since-3.0 | document-as-needing-environment | parent_comm in [nginx,apache2,httpd,php-fpm…] AND comm regex [^sh$,^bash$,^dash$,^zsh$…] |
| `web_sql_injection_command` | Z1 | syscall | `web-attacks-enhanced.yaml:59` | yes | condition-changed-since-3.0 | merge-with-duplicate | nr in [59,322,545] AND parent_comm in [nginx,apache2,httpd,php-fpm…] |
| `webshell_command_injection_patterns` | Z1 | syscall | `webshell-detection.yaml:266` | no | silent-no-input | document-as-needing-environment | proc.args regex [;\s*(id\|whoami\|uname\|cat /etc/passwd),\\|\s*(id\|whoami\|uname -a),\$\(id\),`id`…] |
| `webshell_java_runtime_exec` | Z1 | syscall | `webshell-detection.yaml:532` | no | silent-no-input | document-as-needing-environment | proc.args regex [java.*-jar.*[^/]+\.jar,java.*RuntimeExec,java.*ProcessBuilder] |
| `webshell_php_disable_functions_bypass` | Z1 | syscall | `webshell-detection.yaml:304` | no | silent-no-input | document-as-needing-environment | proc.args regex [php.*passthru,php.*shell_exec,php.*proc_open,php.*popen…] |
| `webshell_php_eval_pattern` | Z1 | syscall | `webshell-detection.yaml:287` | no | silent-no-input | document-as-needing-environment | proc.args regex [php.*eval.*base64_decode,php.*assert.*base64,php.*eval.*gzinflate,php.*eval.*str_rot13…] |
| `appexploit_java_deser_network_port` | Z2 | tcp_connect | `application-exploits.yaml:127` | no | silent-no-input | document-as-needing-environment | dport in [1099,1100,8009,4848…] |
| `appexploit_log4shell_ldap_port` | Z2 | tcp_connect | `application-exploits.yaml:28` | no | silent-no-input | document-as-needing-environment | dport in [1389,1099,389,636] |
| `appexploit_log4shell_rmi_port` | Z2 | tcp_connect | `application-exploits.yaml:40` | no | silent-no-input | document-as-needing-environment | dport in [1099,1100,1098] |
| `appexploit_ssrf_gcp_metadata` | Z2 | tcp_connect | `application-exploits.yaml:329` | no | silent-no-input | merge-with-duplicate | daddr in [169.254.169.254,metadata.google.internal] |
| `c2_connect_to_tor_port` | Z2 | tcp_connect | `command-and-control.yaml:248` | no | silent-no-input | document-as-needing-environment | network.dport in [9050,9150,9051,9151] |
| `c2_high_port_outbound` | Z2 | tcp_connect | `command-and-control.yaml:263` | no | silent-no-input | document-as-needing-environment | network.dport gt [40000] AND proc.comm not_in [kubectl,docker,containerd,etcd…] |
| `c2_reverse_shell_standard_ports` | Z2 | tcp_connect | `command-and-control.yaml:3` | no | silent-no-input | document-as-needing-environment | proc.comm in [bash,sh,zsh,dash…] AND network.dport not_in [53,123] |
| `cloud_ext_aws_imds_v1_access` | Z2 | tcp_connect | `cloud-attacks-extended.yaml:10` | no | silent-no-input | document-as-needing-environment | daddr in [169.254.169.254] |
| `cloud_ext_gcp_compute_metadata_access` | Z2 | tcp_connect | `cloud-attacks-extended.yaml:194` | no | silent-no-input | merge-with-duplicate | daddr in [169.254.169.254,metadata.google.internal] |
| `cloud_ext_k8s_etcd_access` | Z2 | tcp_connect | `cloud-attacks-extended.yaml:322` | no | silent-no-input | merge-with-duplicate | dport in [2379,2380] |
| `drift_new_network_common_c2_ports` | Z2 | tcp_connect | `drift-rules.yaml:238` | no | silent-no-input | document-as-needing-environment | dport in [4444,8080,8443,31337…] |
| `exfil_ftp_active_connection` | Z2 | tcp_connect | `exfiltration-extended.yaml:368` | no | silent-no-input | document-as-needing-environment | network.dport equals [21] |
| `exfil_scp_from_container` | Z2 | tcp_connect | `data-exfiltration.yaml:239` | no | silent-no-input | document-as-needing-environment | dport in [22,2222,2022] |
| `initial_java_jndi_ldap` | Z2 | tcp_connect | `initial-access.yaml:210` | no | silent-no-input | document-as-needing-environment | proc.comm in [java,java8,java11,java17…] AND network.dport in [389,636,1389,1636] |
| `initial_ssh_login_new_user` | Z2 | tcp_connect | `initial-access.yaml:189` | no | silent-no-input | document-as-needing-environment | network.dport equals [22] AND proc.comm equals [sshd] |
| `initial_trusted_api_pivot` | Z2 | tcp_connect | `initial-access.yaml:295` | no | silent-no-input | document-as-needing-environment | proc.comm in [nginx,apache2,httpd,node…] AND network.dport in [6443,8200,8201,5432…] |
| `lateral_port_forward_ssh` | Z2 | tcp_connect | `lateral-movement.yaml:45` | no | silent-no-input | document-as-needing-environment | proc.comm equals [ssh] AND network.dport not_in [22] |
| `lateral_rdp_connection` | Z2 | tcp_connect | `lateral-movement.yaml:88` | no | silent-no-input | document-as-needing-environment | network.dport equals [3389] |
| `mitre_winrm_port_connection` | Z2 | tcp_connect | `mitre-additional.yaml:631` | no | silent-no-input | document-as-needing-environment | dport in [5985,5986] |
| `netintr_brute_ratel_port` | Z2 | tcp_connect | `network-intrusion.yaml:374` | no | silent-no-input | document-as-needing-environment | dport in [53311,8443] |
| `netintr_cobalt_strike_default_port` | Z2 | tcp_connect | `network-intrusion.yaml:350` | no | silent-no-input | document-as-needing-environment | dport in [50050] |
| `netintr_connection_to_multicast` | Z2 | tcp_connect | `network-intrusion.yaml:469` | no | silent-no-input | document-as-needing-environment | daddr in_cidr [224.0.0.0/4] |
| `netintr_covenant_default_port` | Z2 | tcp_connect | `network-intrusion.yaml:362` | no | silent-no-input | document-as-needing-environment | dport in [7443] |
| `netintr_ftp_data_exfil` | Z2 | tcp_connect | `network-intrusion.yaml:270` | no | silent-no-input | document-as-needing-environment | dport in [20,21] |
| `netintr_high_port_established` | Z2 | tcp_connect | `network-intrusion.yaml:46` | no | silent-no-input | document-as-needing-environment | dport gt [49152] |
| `netintr_nmap_fingerprint_ports` | Z2 | tcp_connect | `network-intrusion.yaml:85` | no | silent-no-input | document-as-needing-environment | dport in [7,9,13,17…] |
| `netintr_outbound_smb` | Z2 | tcp_connect | `network-intrusion.yaml:97` | no | silent-no-input | document-as-needing-environment | dport in [445,139] |
| `netintr_rdp_outbound` | Z2 | tcp_connect | `network-intrusion.yaml:545` | no | silent-no-input | document-as-needing-environment | dport in [3389,3388] |
| `netintr_reverse_shell_port_1234` | Z2 | tcp_connect | `network-intrusion.yaml:22` | no | silent-no-input | document-as-needing-environment | dport in [1234,5555,6666,7777…] |
| `netintr_reverse_shell_port_31337` | Z2 | tcp_connect | `network-intrusion.yaml:34` | no | silent-no-input | document-as-needing-environment | dport in [31337,12345,54321] |
| `netintr_reverse_shell_port_4444` | Z2 | tcp_connect | `network-intrusion.yaml:10` | no | silent-no-input | document-as-needing-environment | dport in [4444] |
| `netintr_smtp_exfil` | Z2 | tcp_connect | `network-intrusion.yaml:282` | no | silent-no-input | document-as-needing-environment | dport in [25,465,587] |
| `netintr_socks_proxy_port` | Z2 | tcp_connect | `network-intrusion.yaml:118` | no | silent-no-input | document-as-needing-environment | dport in [1080,1081,1082,3128…] |
| `netintr_vnc_outbound` | Z2 | tcp_connect | `network-intrusion.yaml:557` | no | silent-no-input | document-as-needing-environment | dport in [5900,5901,5902,5903…] |
| `owasp_web_metadata_access` | Z2 | tcp_connect | `owasp-web.yaml:226` | no | silent-no-input | document-as-needing-environment | daddr in [169.254.169.254,100.100.100.200] |
| `sigma_irc_c2_ports` | Z2 | tcp_connect | `sigma-linux.yaml:1788` | no | silent-no-input | document-as-needing-environment | dport in [6667,6668,6669,6697] |
| `sigma_outbound_tor_ports` | Z2 | tcp_connect | `sigma-linux.yaml:1776` | no | silent-no-input | document-as-needing-environment | dport in [9001,9030,9050,9051] |
| `sigma_ssh_many_failed_auth` | Z2 | tcp_connect | `sigma-linux.yaml:1655` | no | silent-no-input | document-as-needing-environment | dport in [22,2222,22222] |
| `webshell_ssrf_aws_metadata` | Z2 | tcp_connect | `webshell-detection.yaml:325` | no | silent-no-input | document-as-needing-environment | daddr in [169.254.169.254,fd00:ec2::254] |
| `net_long_c2_connection` | Z3 | net_close | `network-anomaly.yaml:5` | no | silent-no-input | document-as-needing-environment | dport in [4444,1337,31337,8888…] AND duration_sec gt [300] |
| `net_long_https_connection` | Z3 | net_close | `network-anomaly.yaml:57` | no | silent-no-input | document-as-needing-environment | dport equals [443] AND duration_sec gt [3600] |
| `net_long_plaintext_http` | Z3 | net_close | `network-anomaly.yaml:35` | no | silent-no-input | document-as-needing-environment | dport equals [80] AND duration_sec gt [300] |
| `net_long_ssh_session` | Z3 | net_close | `network-anomaly.yaml:267` | no | silent-no-input | document-as-needing-environment | dport equals [22] AND duration_sec gt [259200] |
| `netintr_persistent_c2_beacon` | Z3 | net_close | `network-intrusion.yaml:533` | no | silent-no-input | document-as-needing-environment | duration_sec gt [3600] |
| `appexploit_cmd_injection_nc` | Z4 | file | `application-exploits.yaml:232` | no | silent-no-input | document-as-needing-environment | filename regex [.*/nc$,.*/ncat$,.*/netcat$,.*/nc\.openbsd$…] |
| `appexploit_cmd_injection_whoami` | Z4 | file | `application-exploits.yaml:216` | no | silent-no-input | document-as-needing-environment | filename in [/usr/bin/whoami,/usr/bin/id,/bin/id,/usr/bin/uname] |
| `appexploit_containerd_socket_access` | Z4 | file | `application-exploits.yaml:445` | no | silent-no-input | document-as-needing-environment | filename in [/run/containerd/containerd.sock,/var/run/containerd/containerd.sock] |
| `appexploit_cri_socket_access` | Z4 | file | `application-exploits.yaml:459` | no | silent-no-input | merge-with-duplicate | filename in [/var/run/crio/crio.sock,/run/crio/crio.sock] |
| `appexploit_docker_socket_access` | Z4 | file | `application-exploits.yaml:431` | no | silent-no-input | document-as-needing-environment | filename in [/var/run/docker.sock,/run/docker.sock] |
| `appexploit_lfi_log_poisoning` | Z4 | file | `application-exploits.yaml:309` | no | silent-no-input | document-as-needing-environment | filename prefix [/var/log/apache2/,/var/log/nginx/,/var/log/httpd/,/var/log/php/] |
| `appexploit_spring4shell_file_write` | Z4 | file | `application-exploits.yaml:56` | no | silent-no-input | document-as-needing-environment | filename regex [/opt/tomcat/webapps/ROOT/.*\.jsp$,/var/lib/tomcat.*/webapps/ROOT/.*\.jsp$] |
| `appexploit_struts2_ognl_shell` | Z4 | file | `application-exploits.yaml:74` | no | silent-no-input | document-as-needing-environment | filename regex [.*/struts2.*\.jsp$,.*/struts.*shell.*\.jsp$] |
| `cis_5_1_3_secret_access` | Z4 | file | `cis-k8s.yaml:26` | no | silent-no-input | document-as-needing-environment | filename prefix [/var/lib/kubelet/pods/,/run/secrets/kubernetes.io/] |
| `collection_direct_db_file_access` | Z4 | file | `collection-and-evasion-gaps.yaml:4` | no | silent-no-input | document-as-needing-environment | file.path prefix [/var/lib/mysql/,/var/lib/postgresql/,/var/lib/mongodb/,/var/lib/redis/…] AND file.op in [open,read] AND proc.comm not_in [mysqld,mariadbd,p… |
| `collection_local_mail_spool_access` | Z4 | file | `collection-and-evasion-gaps.yaml:70` | no | silent-no-input | document-as-needing-environment | file.path prefix [/var/mail/,/var/spool/mail/,/var/spool/postfix/] AND file.op in [open,read] AND proc.comm not_in [postfix,dovecot,exim4,sendmail…] |
| `cred_aws_credentials_read` | Z4 | file | `credential-access.yaml:3` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.aws/credentials,/.aws/config] AND file.op in [read,open] AND proc.comm not_in [aws,terraform,packer,ansible…] |
| `cred_bash_history_read` | Z4 | file | `credential-access.yaml:125` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.bash_history,/.zsh_history,/.sh_history,/.history…] AND file.op in [read,open] AND proc.comm not_in [bash,zsh,sh,fish…] |
| `cred_browser_store_read` | Z4 | file | `credential-access.yaml:182` | no | silent-no-input | document-as-needing-environment | file.path suffix [/Login Data,/Login Data-journal,/logins.json,/key4.db…] AND file.op in [read,open] AND proc.comm not_in [chrome,chromium,firefox,brave…] |
| `cred_docker_auth_read` | Z4 | file | `credential-access.yaml:156` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.docker/config.json,/.dockerconfigjson] AND file.op in [read,open] AND proc.comm not_in [docker,podman,containerd,buildkit…] |
| `cred_gcp_service_account_read` | Z4 | file | `credential-access.yaml:30` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/gcp/,/etc/google/,/run/secrets/google] AND file.path suffix [.json] AND file.op in [read,open] AND proc.comm not_in [gcloud,python3,py… |
| `cred_ssh_private_key_read` | Z4 | file | `credential-access.yaml:59` | no | silent-no-input | document-as-needing-environment | file.path suffix [/id_rsa,/id_ed25519,/id_ecdsa,/id_dsa…] AND file.op in [read,open] AND proc.comm not_in [ssh,scp,sftp,ssh-agent…] |
| `cred_vault_token_read` | Z4 | file | `credential-access.yaml:214` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.vault-token,/.vault/token,/vault-token] AND file.op in [read,open] AND proc.comm not_in [vault,consul,nomad,terraform…] |
| `credaccess_pam_config_backdoor` | Z4 | file | `credential-and-defense-gaps.yaml:5` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/pam.d/,/etc/pam.conf] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `credaccess_ssh_authorized_keys_modified` | Z4 | file | `credential-and-defense-gaps.yaml:34` | no | silent-no-input | document-as-needing-environment | file.path suffix [authorized_keys,authorized_keys2] AND file.op in [create,write] AND proc.comm not_in [ssh,sshd,ssh-copy-id,scp…] |
| `defense_evasion_binary_truncate_pad` | Z4 | file | `collection-and-evasion-gaps.yaml:42` | no | silent-no-input | document-as-needing-environment | proc.comm in [truncate,dd,fallocate] AND file.path prefix [/usr/bin/,/usr/sbin/,/bin/,/sbin/…] AND file.op in [write,truncate] |
| `evasion_system_binary_replace` | Z4 | file | `defense-evasion.yaml:100` | no | silent-no-input | document-as-needing-environment | file.path prefix [/bin/,/sbin/,/usr/bin/,/usr/sbin/…] AND file.op in [write,create,rename] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `execution_motd_hook_exec` | Z4 | file | `collection-and-evasion-gaps.yaml:190` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/update-motd.d/] AND file.path suffix [.sh,.py,.pl,.rb] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `exfil_clipboard_tool_network` | Z4 | file | `data-exfiltration.yaml:214` | no | silent-no-input | document-as-needing-environment | filename prefix [/proc/self/mem,/dev/shm/] |
| `exfil_usb_mount` | Z4 | file | `exfiltration-extended.yaml:201` | no | silent-no-input | document-as-needing-environment | file.path prefix [/media/,/mnt/usb,/run/media/] AND file.op in [create,write] AND proc.comm not_in [udisks2,udisksd,udevadm,systemd-udevd…] |
| `exfil_wayland_socket_access` | Z4 | file | `data-exfiltration.yaml:116` | no | silent-no-input | document-as-needing-environment | filename regex [/run/user/[0-9]+/wayland-[0-9]+,/var/run/user/[0-9]+/wayland-[0-9]+] |
| `exfil_x11_socket_access` | Z4 | file | `data-exfiltration.yaml:96` | no | silent-no-input | document-as-needing-environment | filename regex [/tmp/\.X11-unix/X[0-9]+,/tmp/\.X[0-9]+-lock] |
| `fim_apparmor_profile_modified` | Z4 | file | `file-integrity-extended.yaml:345` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/apparmor.d/,/etc/apparmor/] |
| `fim_audit_rules_modified` | Z4 | file | `file-integrity-extended.yaml:326` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/audit/,/etc/audit/rules.d/] |
| `fim_binary_replaced_in_system_dir` | Z4 | file | `file-integrity-extended.yaml:11` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename regex [^/usr/bin/[^/]+$,^/usr/sbin/[^/]+$,^/bin/[^/]+$,^/sbin/[^/]+$] |
| `fim_ca_cert_modified` | Z4 | file | `file-integrity-extended.yaml:558` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/ssl/certs/,/usr/local/share/ca-certificates/,/etc/ca-certificates.conf,/etc/pki/ca-trust/] |
| `fim_containerd_config_modified` | Z4 | file | `file-integrity-extended.yaml:514` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/containerd/,/var/lib/containerd/] |
| `fim_docker_config_modified` | Z4 | file | `file-integrity-extended.yaml:495` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/docker/,/var/lib/docker/daemon.json] |
| `fim_init_d_script_written` | Z4 | file | `file-integrity-extended.yaml:234` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/init.d/] |
| `fim_library_replaced` | Z4 | file | `file-integrity-extended.yaml:35` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename regex [^/lib/.*\.so(\.[0-9]+)*$,^/usr/lib/.*\.so(\.[0-9]+)*$,^/lib64/.*\.so(\.[0-9]+)*$,^/usr/lib64/.*\.so(\.[0-9]+)*$] |
| `fim_network_config_modified` | Z4 | file | `file-integrity-extended.yaml:470` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/network/interfaces,/etc/netplan/,/etc/sysconfig/network-scripts/,/etc/NetworkManager/system-connections/] |
| `fim_polkit_policy_modified` | Z4 | file | `file-integrity-extended.yaml:406` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/usr/share/polkit-1/actions/,/etc/polkit-1/,/var/lib/polkit-1/] |
| `fim_private_key_written` | Z4 | file | `file-integrity-extended.yaml:579` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename regex [/tmp/.*\.(pem\|key\|crt\|pfx\|p12\|jks)$,/dev/shm/.*\.(pem\|key\|crt\|pfx\|p12\|jks)$,/var/tmp/.*\.(pem\|key\|crt\|pfx\|p12… |
| `fim_rc_local_modified` | Z4 | file | `file-integrity-extended.yaml:214` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename in [/etc/rc.local,/etc/rc.d/rc.local,/etc/init.d/rc.local] |
| `fim_selinux_config_modified` | Z4 | file | `file-integrity-extended.yaml:364` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename in [/etc/selinux/config,/etc/selinux/targeted/booleans.conf] |
| `fim_ssh_known_hosts_modified` | Z4 | file | `file-integrity-extended.yaml:280` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename regex [.*/\.ssh/known_hosts$,/etc/ssh/ssh_known_hosts$] |
| `fim_sudoers_written` | Z4 | file | `file-integrity-extended.yaml:387` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/sudoers,/etc/sudoers.d/] |
| `fim_syslog_modified` | Z4 | file | `file-integrity-extended.yaml:303` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/etc/syslog.conf,/etc/rsyslog.conf,/etc/rsyslog.d/,/etc/syslog-ng/…] |
| `initial_web_shell_write` | Z4 | file | `initial-access.yaml:3` | no | silent-no-input | document-as-needing-environment | file.path prefix [/var/www/,/srv/www/,/usr/share/nginx/,/opt/tomcat/…] AND file.path suffix [.php,.php5,.phtml,.phar…] AND file.op in [create,write] AND proc… |
| `integrity_container_runtime_modified` | Z4 | file | `runtime-integrity.yaml:140` | no | silent-no-input | document-as-needing-environment | file.path prefix [/usr/bin/containerd,/usr/bin/dockerd,/usr/bin/docker,/usr/bin/runc…] AND file.op in [write,create,rename] |
| `integrity_grub_bootloader_write` | Z4 | file | `runtime-integrity.yaml:170` | no | silent-no-input | document-as-needing-environment | file.path prefix [/boot/grub/,/boot/grub2/,/boot/efi/,/etc/grub.d/…] AND file.op in [write,create] AND proc.comm not_in [grub-install,grub2-install,update-gr… |
| `integrity_ld_cache_write` | Z4 | file | `runtime-integrity.yaml:58` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/ld.so.conf.d/,/etc/ld.so.conf] AND file.op in [write,create] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `integrity_ld_so_preload_write` | Z4 | file | `runtime-integrity.yaml:37` | no | silent-no-input | document-as-needing-environment | file.path equals [/etc/ld.so.preload] AND file.op in [write,create] |
| `integrity_lib_replaced` | Z4 | file | `runtime-integrity.yaml:3` | no | silent-no-input | document-as-needing-environment | file.path prefix [/lib/,/lib64/,/usr/lib/,/usr/lib64/…] AND file.path suffix [.so,.so.0,.so.1,.so.2…] AND file.op in [write,create,rename] AND proc.comm not_… |
| `integrity_sysctl_security_disable` | Z4 | file | `runtime-integrity.yaml:83` | no | silent-no-input | document-as-needing-environment | file.path prefix [/proc/sys/kernel/randomize_va_space,/proc/sys/kernel/kptr_restrict,/proc/sys/kernel/dmesg_restrict,/proc/sys/kernel/perf_event_paranoid…] A… |
| `lateral_shared_volume_exec` | Z4 | file | `lateral-movement.yaml:172` | no | silent-no-input | document-as-needing-environment | file.path prefix [/data/,/shared/,/mnt/,/srv/] AND file.path suffix [.sh,.py,.pl,.rb…] AND file.op in [create,write] AND uid equals [0] |
| `lateral_ssh_agent_socket_access` | Z4 | file | `lateral-movement.yaml:125` | no | silent-no-input | document-as-needing-environment | file.path prefix [/tmp/ssh-] AND file.op in [open,connect] AND proc.comm not_in [ssh,scp,sftp,git…] |
| `lolbin_busybox_shell` | Z4 | file | `living-off-the-land.yaml:90` | no | silent-no-input | document-as-needing-environment | filename regex [.*/busybox$,/bin/busybox,/usr/bin/busybox] |
| `lolbin_strace_exec` | Z4 | file | `living-off-the-land.yaml:43` | no | silent-no-input | document-as-needing-environment | filename in [/usr/bin/strace,/bin/strace] |
| `mitre_at_job_scheduled` | Z4 | file | `mitre-additional.yaml:647` | no | silent-no-input | document-as-needing-environment | filename in [/usr/bin/at,/usr/bin/atrm,/usr/bin/atq,/var/spool/at] |
| `mitre_dbus_config_modified` | Z4 | file | `mitre-additional.yaml:110` | no | silent-no-input | document-as-needing-environment | filename prefix [/etc/dbus-1/system.d/,/usr/share/dbus-1/system.d/] |
| `mitre_keytab_file_read` | Z4 | file | `mitre-additional.yaml:496` | no | silent-no-input | document-as-needing-environment | filename regex [.*\.keytab$,/etc/krb5\.keytab,/etc/krb5/krb5\.keytab,/var/kerberos/krb5/.*\.keytab$] |
| `mitre_krb5_ccache_read` | Z4 | file | `mitre-additional.yaml:512` | no | silent-no-input | document-as-needing-environment | filename regex [/tmp/krb5cc_[0-9]+,/tmp/krb5cc_.*,/run/user/[0-9]+/krb5cc] |
| `mitre_masq_double_extension` | Z4 | file | `mitre-additional.yaml:92` | no | silent-no-input | document-as-needing-environment | filename regex [.*\.(pdf\|doc\|docx\|xls\|xlsx\|jpg\|png\|gif)\.(sh\|py\|pl\|rb\|exe\|elf\|bin)$,.*\.(sh\|py\|pl\|rb)\.pdf$] |
| `mitre_masq_legitimate_name_in_tmp` | Z4 | file | `mitre-additional.yaml:78` | no | silent-no-input | document-as-needing-environment | filename regex [/tmp/(sshd\|nginx\|apache2\|httpd\|java\|python\|node\|bash\|sh\|ls\|ps\|curl\|wget)$,/dev/shm/(sshd\|nginx\|apache2\|httpd\|java\|python\|no… |
| `mitre_newuidmap_newgidmap` | Z4 | file | `mitre-additional.yaml:196` | no | silent-no-input | document-as-needing-environment | filename in [/usr/bin/newuidmap,/usr/bin/newgidmap,/bin/newuidmap,/bin/newgidmap] |
| `mitre_ngrok_tunnel` | Z4 | file | `mitre-additional.yaml:143` | no | silent-no-input | document-as-needing-environment | filename regex [.*/ngrok$,.*/frp[cs]$,.*/chisel$,.*/ligolo$…] |
| `mitre_software_enum_dpkg` | Z4 | file | `mitre-additional.yaml:422` | no | silent-no-input | document-as-needing-environment | filename in [/var/lib/dpkg/status,/var/lib/rpm/Packages,/var/lib/rpm/rpmdb.sqlite] |
| `mitre_software_enum_security_tools` | Z4 | file | `mitre-additional.yaml:437` | no | silent-no-input | document-as-needing-environment | filename prefix [/etc/falco/,/etc/osquery/,/opt/splunk/,/opt/elastic/…] |
| `mitre_ssh_agent_forward_abuse` | Z4 | file | `mitre-additional.yaml:617` | no | silent-no-input | document-as-needing-environment | filename regex [/tmp/ssh-[A-Za-z0-9]+/agent\.[0-9]+,/run/user/[0-9]+/ssh-[A-Za-z0-9]+/agent\.[0-9]+] |
| `mitre_sslstrip_proxy` | Z4 | file | `mitre-additional.yaml:479` | no | silent-no-input | document-as-needing-environment | filename regex [.*(sslstrip\|mitmproxy\|bettercap\|ettercap\|arpspoof)$] |
| `mitre_token_impersonation_su` | Z4 | file | `mitre-additional.yaml:182` | no | silent-no-input | document-as-needing-environment | filename in [/bin/su,/usr/bin/su] |
| `mitre_vm_detect_dmi_read` | Z4 | file | `mitre-additional.yaml:373` | no | silent-no-input | document-as-needing-environment | filename prefix [/sys/class/dmi/id/,/sys/firmware/dmi/] |
| `owasp_backup_config_access` | Z4 | file | `owasp-web.yaml:342` | no | silent-no-input | document-as-needing-environment | filename regex [\.sql$,\.bak$,\.backup$,\.old$…] |
| `owasp_package_manager_access` | Z4 | file | `owasp-web.yaml:245` | no | silent-no-input | document-as-needing-environment | filename regex [node_modules/.*\.js$,site-packages/.*\.py$,vendor/.*\.php$] |
| `owasp_php_in_upload` | Z4 | file | `owasp-web.yaml:325` | no | silent-no-input | document-as-needing-environment | filename regex [/uploads/.*\.php,/upload/.*\.php,/files/.*\.php,/attachments/.*\.php] |
| `owasp_web_suspicious_write` | Z4 | file | `owasp-web.yaml:176` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename prefix [/var/www/,/srv/www/,/usr/share/nginx/html/,/app/public/…] |
| `persist_apache_conf_write` | Z4 | file | `persistence-extended.yaml:200` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/apache2/,/etc/httpd/,/etc/nginx/,/usr/local/etc/nginx/] AND file.path suffix [.conf,.load] AND file.op in [create,write] AND proc.comm… |
| `persist_etc_environment_write` | Z4 | file | `persistence-extended.yaml:88` | no | silent-no-input | document-as-needing-environment | file.path equals [/etc/environment] AND file.op in [write] AND proc.comm not_in [dpkg,rpm,ansible,puppet…] |
| `persist_etc_profile_write` | Z4 | file | `persistence-extended.yaml:175` | no | silent-no-input | document-as-needing-environment | file.path equals [/etc/profile] AND file.op in [write] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `persist_git_hook_write` | Z4 | file | `persistence-extended.yaml:144` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.git/hooks/pre-commit,/.git/hooks/post-commit,/.git/hooks/post-merge,/.git/hooks/post-checkout…] AND file.op in [create,write] AND proc.co… |
| `persist_profile_d_write` | Z4 | file | `persistence-extended.yaml:62` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/profile.d/] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `persist_sshd_config_write` | Z4 | file | `persistence-extended.yaml:234` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/ssh/sshd_config,/etc/ssh/sshd_config.d/] AND file.op in [write,create] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `persist_systemd_path_unit` | Z4 | file | `persistence-extended.yaml:262` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/systemd/system/,/usr/local/lib/systemd/system/,/run/systemd/system/] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,… |
| `persist_systemd_timer_created` | Z4 | file | `persistence-extended.yaml:3` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/systemd/system/,/usr/local/lib/systemd/system/,/run/systemd/system/,/home/…] AND file.op in [create,write] AND proc.comm not_in [dpkg,… |
| `persist_xdg_autostart_write` | Z4 | file | `persistence-extended.yaml:113` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/xdg/autostart/,/home/] AND file.path suffix [.desktop] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,gnome-session…] |
| `persistence_at_spool_write` | Z4 | file | `persistence.yaml:226` | no | silent-no-input | document-as-needing-environment | file.path prefix [/var/spool/atjobs/,/var/spool/at/] AND file.op in [create,write] AND proc.comm not_in [at,atd,batch] |
| `persistence_cron_write` | Z4 | file | `persistence.yaml:30` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/cron.d/,/etc/cron.daily/,/etc/cron.hourly/,/etc/cron.weekly/…] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `persistence_etc_init_write` | Z4 | file | `persistence.yaml:147` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/init.d/,/etc/rc.d/,/etc/rc.local,/etc/rc2.d/…] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `persistence_ld_preload_env` | Z4 | file | `persistence.yaml:200` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.bashrc,/.profile,/.bash_profile,/etc/environment…] AND file.op in [write,create] |
| `persistence_motd_write` | Z4 | file | `persistence.yaml:177` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/update-motd.d/,/etc/motd] AND file.op in [write,create] |
| `persistence_pam_modified` | Z4 | file | `persistence.yaml:83` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/pam.d/,/lib/security/,/lib64/security/,/usr/lib/security/…] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,yum…] |
| `persistence_shell_rc_write` | Z4 | file | `persistence.yaml:113` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.bashrc,/.bash_profile,/.bash_login,/.profile…] AND file.op in [write] AND proc.comm not_in [bash,zsh,fish,sh…] |
| `persistence_ssh_authorized_keys` | Z4 | file | `persistence.yaml:61` | no | silent-no-input | document-as-needing-environment | file.path suffix [/.ssh/authorized_keys,/.ssh/authorized_keys2] AND file.op in [create,write] |
| `persistence_systemd_new_service` | Z4 | file | `persistence.yaml:3` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/systemd/system/,/usr/local/lib/systemd/system/,/run/systemd/system/] AND file.op in [create,write] AND proc.comm not_in [dpkg,rpm,apt,… |
| `persistence_systemd_service_created` | Z4 | file | `credential-and-defense-gaps.yaml:111` | no | silent-no-input | document-as-needing-environment | file.path suffix [.service] AND file.path prefix [/etc/systemd/system/,/lib/systemd/system/,/usr/lib/systemd/system/,/run/systemd/system/] AND file.op in [cr… |
| `proc_inject_devshm_so` | Z4 | file | `process-injection.yaml:202` | no | silent-no-input | document-as-needing-environment | filename regex [/dev/shm/.*\.so(\.[0-9]+)*,/dev/shm/.*\.so$] |
| `proc_inject_ld_preload_conf` | Z4 | file | `process-injection.yaml:156` | no | silent-no-input | document-as-needing-environment | filename prefix [/etc/ld.so.conf.d/] |
| `proc_inject_ld_preload_file` | Z4 | file | `process-injection.yaml:135` | no | silent-no-input | document-as-needing-environment | filename in [/etc/ld.so.preload] |
| `proc_inject_maps_recon` | Z4 | file | `process-injection.yaml:178` | no | silent-no-input | document-as-needing-environment | filename regex [/proc/[0-9]+/maps,/proc/[0-9]+/pagemap,/proc/[0-9]+/smaps] |
| `proc_inject_proc_mem_write` | Z4 | file | `process-injection.yaml:111` | no | silent-no-input | document-as-needing-environment | filename regex [/proc/[0-9]+/mem] |
| `recon_sudo_privs` | Z4 | file | `reconnaissance.yaml:111` | no | silent-no-input | document-as-needing-environment | file.path prefix [/etc/sudoers.d/,/etc/sudoers] AND file.op in [read,open] AND proc.comm not_in [sudo,sudoedit,visudo,ansible…] |
| `sigma_crontab_modification` | Z4 | file | `sigma-linux.yaml:163` | no | silent-no-input | document-as-needing-environment | filename in [/etc/crontab,/etc/cron.allow,/etc/cron.deny] |
| `sigma_dev_mem_access` | Z4 | file | `sigma-linux.yaml:1618` | no | silent-no-input | document-as-needing-environment | filename in [/dev/mem,/dev/kmem,/dev/port] |
| `sigma_history_file_cleared` | Z4 | file | `sigma-linux.yaml:566` | no | silent-no-input | document-as-needing-environment | filename regex [.*\.bash_history$,.*\.zsh_history$,.*\.history$,.*\.sh_history$] |
| `sigma_java_child_shell` | Z4 | file | `sigma-linux.yaml:1755` | no | silent-no-input | document-as-needing-environment | filename regex [/bin/sh,/bin/bash,/bin/dash,/usr/bin/sh…] |
| `sigma_masquerade_sshd` | Z4 | file | `sigma-linux.yaml:282` | no | silent-no-input | document-as-needing-environment | filename regex [/tmp/sshd,/dev/shm/sshd,/var/tmp/sshd,/tmp/ssh] |
| `sigma_proc_sysrq_write` | Z4 | file | `sigma-linux.yaml:1633` | no | silent-no-input | document-as-needing-environment | op eq [write] AND filename in [/proc/sysrq-trigger] |
| `sigma_sudo_config_read` | Z4 | file | `sigma-linux.yaml:1300` | no | silent-no-input | document-as-needing-environment | filename prefix [/etc/sudoers,/etc/sudoers.d/] |
| `sigma_systemd_timer_created` | Z4 | file | `sigma-linux.yaml:198` | no | silent-no-input | document-as-needing-environment | filename regex [/etc/systemd/system/[^/]+\.timer,/usr/lib/systemd/system/[^/]+\.timer] |
| `supply_chain_build_tool_rootwrite` | Z4 | file | `supply-chain.yaml:202` | no | silent-no-input | document-as-needing-environment | op eq [write] AND proc.comm in [gcc,cc1,clang,make…] AND filename prefix [/usr/bin/,/usr/sbin/,/usr/lib/,/usr/local/bin/…] |
| `web_combined_attack` | Z4 | file | `web-attacks-enhanced.yaml:344` | no | silent-no-input | document-as-needing-environment | filename regex [(union.*select\|or\s+1\s*=\s*1\|drop\s+table).*.*(\.\.\|%2e\|%2f\|%5c),(<script\|javascript:\|innerHTML).*(php://\|file://\|data://),(\{\{\|\… |
| `web_file_inclusion_attack` | Z4 | file | `web-attacks-enhanced.yaml:211` | no | silent-no-input | document-as-needing-environment | filename regex [php://input,php://file,expect://,data://…] |
| `web_path_traversal_process` | Z4 | file | `web-attacks-enhanced.yaml:192` | no | silent-no-input | document-as-needing-environment | filename regex [(nginx\|apache\|httpd\|node\|python\|php\|java\|tomcat\|jetty\|lighttpd\|caddy\|traefik\|gunicorn\|uwsgi\|passenger\|mongrel\|webrick).*?(\.\… |
| `web_template_injection` | Z4 | file | `web-attacks-enhanced.yaml:234` | no | silent-no-input | document-as-needing-environment | filename regex [\{\{.*\}\},\{%.*%\},\{#.*#\},\{\$.*\}…] |
| `web_xss_file_pattern` | Z4 | file | `web-attacks-enhanced.yaml:105` | no | silent-no-input | document-as-needing-environment | filename regex [<script,%3Cscript,%253Cscript,javascript:…] |
| `webshell_apache_config_modified` | Z4 | file | `webshell-detection.yaml:468` | no | silent-no-input | document-as-needing-environment | filename prefix [/etc/apache2/conf-enabled/,/etc/apache2/sites-enabled/,/etc/apache2/mods-enabled/,/etc/httpd/conf.d/…] |
| `webshell_asp_written` | Z4 | file | `webshell-detection.yaml:45` | no | silent-no-input | document-as-needing-environment | filename regex [/var/www/.*\.asp$,/var/www/.*\.aspx$,/srv/www/.*\.asp$,/srv/www/.*\.aspx$] |
| `webshell_common_filename` | Z4 | file | `webshell-detection.yaml:96` | no | silent-no-input | document-as-needing-environment | filename regex [.*(c99\|r57\|b374k\|wso\|alfa\|indoxploit\|shell\|webshell\|backdoor\|cmd\|eval\|passthru\|exec\|cmd)\.php$,.*(upload\|uploader\|filemanager)… |
| `webshell_curl_from_web_proc` | Z4 | file | `webshell-detection.yaml:547` | no | silent-no-input | document-as-needing-environment | filename in [/usr/bin/curl,/usr/bin/wget,/bin/curl,/bin/wget…] |
| `webshell_htaccess_modification` | Z4 | file | `webshell-detection.yaml:433` | no | silent-no-input | document-as-needing-environment | filename regex [/var/www/.*\.htaccess$,/srv/www/.*\.htaccess$,/htdocs/.*\.htaccess$] |
| `webshell_image_extension_script` | Z4 | file | `webshell-detection.yaml:111` | no | silent-no-input | document-as-needing-environment | filename regex [/var/www/.*\.(jpg\|jpeg\|png\|gif\|ico\|bmp)\.php$,/var/www/.*\.php\.(jpg\|jpeg\|png\|gif)$] |
| `webshell_jsp_in_web_root` | Z4 | file | `webshell-detection.yaml:28` | no | silent-no-input | document-as-needing-environment | filename regex [/opt/tomcat/webapps/.*\.jsp$,/var/lib/tomcat.*/webapps/.*\.jsp$,/usr/share/tomcat.*/webapps/.*\.jsp$,/opt/jboss/.*\.jsp$…] |
| `webshell_nginx_config_modified` | Z4 | file | `webshell-detection.yaml:452` | no | silent-no-input | document-as-needing-environment | filename prefix [/etc/nginx/conf.d/,/etc/nginx/sites-enabled/,/etc/nginx/sites-available/,/etc/nginx/nginx.conf] |
| `webshell_php_in_web_root` | Z4 | file | `webshell-detection.yaml:10` | no | silent-no-input | document-as-needing-environment | filename regex [/var/www/html/.*\.php$,/var/www/.*\.php$,/srv/www/.*\.php$,/usr/share/nginx/html/.*\.php$…] |
| `webshell_upload_via_image_dir` | Z4 | file | `webshell-detection.yaml:413` | no | silent-no-input | document-as-needing-environment | filename regex [/uploads/.*\.(php\|jsp\|py\|sh\|pl\|rb)$,/upload/.*\.(php\|jsp\|py\|sh\|pl\|rb)$,/images/.*\.(php\|jsp\|py\|sh\|pl\|rb)$,/img/.*\.(php\|jsp\|… |

## 7. Decision counts

| decision | count |
|---|---:|
| document-as-needing-environment | 262 |
| fix-condition | 19 |
| merge-with-duplicate | 9 |
| verify-after-fix | 2 |

`fix-condition` = 19: 12 `nr`-dead + 3 `op`-dead + 4 `proto`-dead rules, whose condition cannot match the collector. The fix (drop/re-key the dead value set, or open the syscall and pay the noise) changes detection semantics and is deferred to the stand/owner (plan item 8) — this wave records the decision, it does not apply it. `verify-after-fix` = 2: already corrected by waves 5–6, needs a stand re-measure. The `document-as-needing-environment` bucket is the actionable backlog for a stand run (scenario per family), not a claim that those rules are wrong. **No rule was deleted, renamed or re-conditioned by this item.**

