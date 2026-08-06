# Rule Set Revision 3.0 — Inventory (2026-08-06)

> Task 3.0 deliverable (plan.md, Wave 3). Pure analysis, **no code changed**. Builds the table `rule -> status -> decision`; for every silent rule a reason is recorded.

## 1. Method

- **Loaded rules:** 591, taken from `/debug/state` `rules[]` of the замер №1 run (build `3a3006a`, 2026-08-05). 586 are defined in `rules/*.yaml`; 5 (`canary_001`..`canary_005`) are generated dynamically from canary config.
- **Fired set:** union of every alert snapshot in `server-logs/` across **all four runs** (`attack-results/*alerts-*.json`, `sqlmap-results/alerts-*.json`, `bruteforce-results/alerts-*.json`) — 14 files, 58 045 alert records.
- **Attacker comms** (from `attack-manifest.json` + plan 1.75c): `curl`, `sqlmap`, `docker-proxy`.
- **System/daemon comms:** sshd, cron, ebpf-guard, systemd-*, dbus, containerd, dockerd, runc, grafana, prometheus, ps/pgrep/ls/find/grep, landscape-sysin, sftp-server, etc.
- **Status** is assigned per rule, NOT per alert:
  - `confirmed-clean` — fired on an attacker comm and never on a daemon (high precision);
  - `confirmed-noisy` — fired on an attacker comm AND on a daemon (low specificity — корень B);
  - `noisy-only` — fired, but only on daemons/self (pure FP source);
  - `silent` — never fired in any of the four runs.
- Validation against the замер №1 report: `new_alerts_total` matches exactly (2007); baseline/final sizes match within snapshot timing tolerance.

## 2. Headline numbers

| Status | Count | Share |
|---|---:|---:|
| confirmed-clean | 5 | 0.8% |
| confirmed-noisy | 37 | 6.3% |
| noisy-only | 58 | 9.8% |
| silent | 491 | 83.1% |
| **TOTAL** | **591** | |

**One sentence:** 83% of the catalog (491/591 rules) never fired in four runs; of the 100 that did, 95 are polluted by daemon/self noise, and only **5 fire on attackers cleanly**.

## 3. The two structural findings

### Finding A — the catalog is 83% unverified, and most of it is environment-blocked, not buggy

Silent rules by reason (full per-rule list in section 7):

| Reason | Count | Class |
|---|---:|---|
| cloud_audit — no cloud provider on the bare-metal docker stend | 34 | env/input-missing |
| gpu — no GPU device on stend | 10 | env/input-missing |
| tls — collector disabled in test config | 23 | env/input-missing |
| dns — collector blind on nss-resolve (P0-26); attacks hit localhost:3000 | 28 | env/input-missing |
| kmod — collector partial (needs LSM) | 8 | env/input-missing |
| cgroup_esc — needs LSM hooks | 4 | env/input-missing |
| http_plaintext — no http collector output | 3 | env/input-missing |
| bpf_subversion — no BPF tampering in test attacks | 8 | attack-not-attempted |
| io_uring — not exercised by attacks | 3 | attack-not-attempted |
| privesc — no successful privesc in attacks (good) | 8 | attack-not-attempted |
| k8s/cloud-k8s — stend is bare docker, not a k8s node | 28 | attack-not-attempted |
| cryptominer — no miner binary executed | 5 | attack-not-attempted |
| ransomware — no mass-encryption attack | 9 | attack-not-attempted |
| rootkit-deploy — no real rootkit artifact deployed | 16 | attack-not-attempted |
| container-escape (file) — escape not attempted; many need LSM | 12 | attack-not-attempted |
| syscall — arg/ret condition not matched | 120 | condition-not-matched (REVIEW) |
| tcp_connect — dest/port pattern not matched | 43 | condition-not-matched (REVIEW) |
| net_close — timing/size pattern not matched | 5 | condition-not-matched (REVIEW) |
| file — watched path/op not touched OR comm condition unmet | 124 | condition-not-matched (REVIEW) |

Of the 491 silent rules: **110** are blocked by the stend environment (no cloud/GPU/TLS/LSM/k8s, DNS blind), **89** simply had no matching attack in the suite, and **292** never matched an event that *did* occur — only these last need a YAML condition review.

**Most extreme case:** of 147 loaded `syscall` rules, exactly **1 fired** in four runs (`mitre_arp_spoof_raw_socket`, 4 times, `comm=""`). The syscall rule body is effectively untested as a whole.

### Finding B — корень B confirmed in the data: one `/etc/passwd` read = 6 rules, ~92% FP

Seven file rules all key on the same `/etc/passwd`|`/etc/shadow` prefix with no comm condition (plan, Q9). One `sshd` login fanned out to 6 alerts each time:

| rule | total | attacker | daemon/self | FP% |
|---|---:|---:|---:|---:|
| `sigma_sensitive_file_chmod` | 3117 | 241 | 2876 | 92% |
| `owasp_web_sensitive_file_read` | 3031 | 230 | 2801 | 92% |
| `appexploit_lfi_passwd_access` | 2999 | 237 | 2762 | 92% |
| `sigma_passwd_shadow_read` | 2999 | 237 | 2762 | 92% |
| `webshell_sensitive_file_read` | 2890 | 243 | 2647 | 92% |
| `appexploit_xxe_file_read` | 2765 | 281 | 2484 | 90% |
| `sensitive_file_read` | 1140 | 367 | 773 | 68% |

Together these 7 produced **~19 850 of the 58 045 alert records (34%)** while carrying the real attacker signal in only ~1 560 (8%). Plan 2.2 already de-duplicates them at the *incident* level (`SourceEvents`); the rules themselves remain the loudest source in the engine and the primary input to `alerts_dropped` (4.6).

## 4. Confirmed rules (42) — KEEP core, tune the noisy fringe

### 4a. `confirmed-clean` (5) — high-precision, do not touch

| rule | count | event_type |
|---|---:|---|
| `net_portscan_indicator` | 1026 | net_close |
| `c2_periodic_beacon_pattern` | 709 | tcp_connect |
| `net_high_frequency_connections` | 643 | tcp_connect |
| `lateral_tool_transfer_wget` | 104 | tcp_connect |
| `sigma_reverse_shell_named_pipe` | 87 | file |

### 4b. `confirmed-noisy` (37) — real signal mixed with noise

Sorted by daemon-noise share. Network rules with FP < 15% are the core detection value of the product (portscan, C2 beacon, SSRF) — leave them. File/drift rules are корень-B candidates.

| rule | total | atk | daemon | FP% | evt | decision |
|---|---:|---:|---:|---:|---|---|
| `drift_new_library_in_system_dir` | 2503 | 89 | 2414 | 96% | file | 3.2 — add toolchain/build comm exception (as,cc1,ld,go,compile,vet) + ebpf-guard self |
| `sigma_sensitive_file_chmod` | 3117 | 241 | 2876 | 92% | file | 3.1 — add comm dimension (Q9) + consolidate: one /etc/passwd read fires 6 rules |
| `owasp_web_sensitive_file_read` | 3031 | 230 | 2801 | 92% | file | 3.1 — add comm dimension (Q9) + consolidate: one /etc/passwd read fires 6 rules |
| `appexploit_lfi_passwd_access` | 2999 | 237 | 2762 | 92% | file | 3.1 — add comm dimension (Q9) + consolidate: one /etc/passwd read fires 6 rules |
| `sigma_passwd_shadow_read` | 2999 | 237 | 2762 | 92% | file | 3.1 — add comm dimension (Q9) + consolidate: one /etc/passwd read fires 6 rules |
| `webshell_sensitive_file_read` | 2890 | 243 | 2647 | 92% | file | 3.1 — add comm dimension (Q9) + consolidate: one /etc/passwd read fires 6 rules |
| `appexploit_xxe_file_read` | 2765 | 281 | 2484 | 90% | file | 3.1 — add comm dimension (Q9) + consolidate: one /etc/passwd read fires 6 rules |
| `sigma_binary_in_tmp_executed` | 658 | 84 | 574 | 87% | file | 3.2 — add toolchain/build comm exception (as,cc1,ld,go,compile,vet) + ebpf-guard self |
| `privesc_suid_suspicious_path` | 654 | 84 | 570 | 87% | file | 3.2 — add toolchain/build comm exception (as,cc1,ld,go,compile,vet) + ebpf-guard self |
| `drift_new_exec_critical` | 584 | 84 | 500 | 86% | file | 3.2 — add toolchain/build comm exception (as,cc1,ld,go,compile,vet) + ebpf-guard self |
| `netintr_syn_scan_pattern` | 121 | 24 | 97 | 80% | tcp_connect | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `initial_package_postinstall_network` | 117 | 24 | 93 | 79% | tcp_connect | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `exfil_outbound_high_port` | 38 | 8 | 30 | 79% | tcp_connect | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `owasp_reverse_shell_pattern` | 38 | 8 | 30 | 79% | tcp_connect | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `evasion_hidden_elf_in_tmp` | 207 | 61 | 146 | 71% | file | 3.2 — add toolchain/build comm exception (as,cc1,ld,go,compile,vet) + ebpf-guard self |
| `sensitive_file_read` | 1140 | 367 | 773 | 68% | file | 3.1 — add comm dimension (Q9) + consolidate: one /etc/passwd read fires 6 rules |
| `fim_passwd_write` | 83 | 27 | 56 | 67% | file | 3.2 — legitimate daemon writes (sshd/cron), add comm+path exception |
| `rootkit_passwd_modified` | 83 | 27 | 56 | 67% | file | 3.2 — legitimate daemon writes (sshd/cron), add comm+path exception |
| `fim_hosts_file_modified` | 26 | 12 | 14 | 54% | file | 3.2 — legitimate daemon writes (sshd/cron), add comm+path exception |
| `exfil_large_http_post` | 108 | 56 | 52 | 48% | tcp_connect | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `netintr_http_on_non_web_port` | 108 | 56 | 52 | 48% | tcp_connect | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `drift_new_file_dir_sensitive` | 833 | 459 | 374 | 45% | file | 3.2 — add toolchain/build comm exception (as,cc1,ld,go,compile,vet) + ebpf-guard self |
| `webshell_script_write_via_web_process` | 150 | 88 | 62 | 41% | file | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `webshell_outbound_high_port` | 12 | 8 | 4 | 33% | tcp_connect | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `rootkit_hidden_dir_dev` | 64 | 52 | 12 | 19% | file | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `fim_resolv_conf_modified` | 50 | 41 | 9 | 18% | file | 3.2 — legitimate daemon writes (sshd/cron), add comm+path exception |
| `mitre_nsswitch_modified` | 50 | 41 | 9 | 18% | file | 3.2 — tune: attacker signal present but mixed with daemon/self noise |
| `beacon_fixed_interval` | 787 | 705 | 82 | 10% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `web_internal_recon` | 764 | 686 | 78 | 10% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `webshell_ssrf_internal_network` | 764 | 686 | 78 | 10% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `exfil_repeated_outbound_to_same_ip` | 742 | 694 | 48 | 6% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `netintr_ssh_non_standard_port` | 169 | 162 | 7 | 4% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `exfil_db_nonstandard_port_connect` | 169 | 165 | 4 | 2% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `owasp_web_ssrf_outbound` | 169 | 165 | 4 | 2% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `supply_chain_cicd_runner_network` | 169 | 165 | 4 | 2% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `webshell_network_connection_web_proc` | 169 | 165 | 4 | 2% | tcp_connect | KEEP — low FP, real network signal (core detection value) |
| `netintr_loopback_high_port` | 980 | 972 | 8 | 1% | tcp_connect | KEEP — low FP, real network signal (core detection value) |

## 5. `noisy-only` (58) — pure FP, the work list for 3.2

Every rule below fired but never on an attacker. Most are legitimate daemon behaviour (sshd/cron/ps/runc) or agent self-I/O (P1-17 remainder). Top offenders first.

| rule | count | event_type | top comms | decision |
|---|---:|---|---|---|
| `cred_proc_maps_mass_read` | 3263 | file | ebpf-guard(2544), grep(686), docker(12), runc:[2:INIT](8) | 3.2 — recon/sandbox rules fire on legitimate inventory (ps/pgrep/find/grep); add comm exception |
| `container_escape_init_proc` | 3066 | file | prometheus(1602), grafana(459), cron(347), systemd-journal(170) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `mitre_sandbox_detect_proc_read` | 2502 | file | ebpf-guard(1670), systemd-logind(168), systemd-journal(152), awk(140) | 3.2 — recon/sandbox rules fire on legitimate inventory (ps/pgrep/find/grep); add comm exception |
| `sigma_failed_login_syscall` | 2354 | file | sshd(1839), cron(511), (systemd)(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `rootkit_pam_module_added` | 2195 | file | sshd(1692), cron(499), (systemd)(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `sigma_log_deletion` | 2089 | file | sshd(1606), systemd-journal(369), landscape-sysin(74), journalctl(36) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `sigma_utmp_wtmp_modified` | 1597 | file | sshd(1587), cron(10) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `recon_sensitive_file_find` | 591 | file | find(591) | 3.2 — recon/sandbox rules fire on legitimate inventory (ps/pgrep/find/grep); add comm exception |
| `sigma_memory_proc_dump` | 431 | file | dbus-daemon(263), landscape-sysin(122), pgrep(32), ps(6) | 3.2 — recon/sandbox rules fire on legitimate inventory (ps/pgrep/find/grep); add comm exception |
| `sigma_cpu_info_access` | 388 | file | ps(96), grep(83), landscape-sysin(79), ebpf-guard(58) | 3.2 — recon/sandbox rules fire on legitimate inventory (ps/pgrep/find/grep); add comm exception |
| `sigma_kernel_version_read` | 380 | file | 00-header(192), 91-release-upgr(188) | 3.2 — recon/sandbox rules fire on legitimate inventory (ps/pgrep/find/grep); add comm exception |
| `supply_chain_pkg_tmp_staging` | 364 | file | ebpf-guard(356), python3(4), sftp-server(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `cred_shadow_read` | 362 | file | cron(362) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `web_sql_injection_files` | 318 | file | systemd-logind(295), systemd-journal(11), systemd-udevd(8), systemd(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `container_escape_proc_write` | 142 | file | irqbalance(103), cron(13), sshd(9), 30-systemd-envi(4) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `netintr_long_dns_session` | 132 | net_close | grafana(128), prometheus(4) | 3.2 — grafana monitoring DNS looks like tunneling; add monitoring-infra exception |
| `netintr_large_upload_port` | 97 | tcp_connect | grafana(89), git-remote-http(4), go(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `container_escape_host_mount` | 90 | file | runc(30), containerd-shim(22), dockerd(22), containerd(16) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `owasp_log_tampering` | 82 | file | landscape-sysin(82) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `cryptominer_xmrig_signature` | 70 | file | docker(50), containerd-shim(8), runc(4), containerd(4) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `owasp_path_traversal` | 56 | file | ld(48), runc:[2:INIT](8) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `web_path_traversal_extended` | 56 | file | ld(48), runc:[2:INIT](8) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `eks_ecr_credential_helper_access` | 50 | file | docker(50) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `rootkit_proc_sysctl_write` | 50 | file | cron(13), sshd(12), systemd(8), 30-systemd-envi(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `mitre_reflective_elf_load` | 46 | file | dockerd(22), containerd-shim(20), containerd(4) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `mitre_so_injection_via_proc` | 46 | file | dockerd(22), containerd-shim(20), containerd(4) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `container_escape_host_network` | 44 | file | systemd-udevd(36), systemd(4), ModemManager(4) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `fim_group_write` | 38 | file | sshd(20), cron(18) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `sigma_sensitive_dir_listing` | 30 | file | ebpf-guard(16), sshd(14) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `fim_profile_modified` | 26 | file | bash(10), cron(9), sshd(7) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `fim_shadow_write` | 22 | file | cron(12), sshd(10) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `container_escape_module_access` | 20 | file | modprobe(16), (e-run.sh)(4) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `canary_004` | 16 | file | ebpf-guard(16) | 3.2 / P1-17 remainder — ebpf-guard self triggering own canaries (self-exclusion gap) |
| `rootkit_ssh_authorized_keys_modified` | 14 | file | sshd(14) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `webshell_crontab_modification` | 13 | file | run-parts(9), ls(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `appexploit_nodejs_child_process` | 8 | file | go(4), perf(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `container_escape_cgroup_v2` | 8 | file | runc:[2:INIT](8) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `exfil_dns_txt_long_label` | 8 | dns | grafana(8) | 3.2 — grafana monitoring DNS looks like tunneling; add monitoring-infra exception |
| `dns_tunneling_long_domain` | 8 | dns | grafana(8) | 3.2 — grafana monitoring DNS looks like tunneling; add monitoring-infra exception |
| `netintr_dns_long_label` | 8 | dns | grafana(8) | 3.2 — grafana monitoring DNS looks like tunneling; add monitoring-infra exception |
| `sigma_tool_download_to_tmp` | 8 | file | python3(4), sftp-server(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `webshell_dns_exfil_long_subdomain` | 8 | dns | grafana(8) | 3.2 — grafana monitoring DNS looks like tunneling; add monitoring-infra exception |
| `canary_001` | 7 | file | ebpf-guard(7) | 3.2 / P1-17 remainder — ebpf-guard self triggering own canaries (self-exclusion gap) |
| `canary_002` | 7 | file | ebpf-guard(7) | 3.2 / P1-17 remainder — ebpf-guard self triggering own canaries (self-exclusion gap) |
| `canary_003` | 7 | file | ebpf-guard(7) | 3.2 / P1-17 remainder — ebpf-guard self triggering own canaries (self-exclusion gap) |
| `canary_005` | 7 | file | ebpf-guard(7) | 3.2 / P1-17 remainder — ebpf-guard self triggering own canaries (self-exclusion gap) |
| `fim_ssh_key_written` | 6 | file | sshd(6) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `container_escape_host_device` | 4 | file | dumpe2fs(4) | 3.2 — fires on container runtime internals (runc/containerd/dockerd); needs comm scoping |
| `proc_keys_read` | 4 | file | runc:[2:INIT](4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `impact_raw_disk_write_from_container` | 4 | file | dumpe2fs(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `mitre_arp_spoof_raw_socket` | 4 | syscall | (4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `rootkit_proc_modules_read` | 4 | file | runc:[2:INIT](4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `rootkit_kcore_access` | 4 | file | runc:[2:INIT](4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `sigma_cron_job_created` | 4 | file | ls(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `sigma_systemd_service_created` | 4 | file | systemd(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `supply_chain_pkg_install_etc_write` | 4 | file | ls(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `supply_chain_lockfile_recon` | 4 | file | go(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |
| `supply_chain_dockerfile_persistence` | 4 | file | ls(4) | 3.2 — pure FP on system daemon; add exception or disable pending review |

## 6. Decisions — what feeds Wave 3.1 / 3.2 / 3.3

| Bucket | Size | Action | Feeds |
|---|---:|---|---|
| confirmed-clean | 5 | keep unchanged | — |
| /etc/passwd file cluster (корень B) | 7 | add comm dimension + consolidate; one read must fire one rule | **3.1** |
| confirmed-noisy build/drift/self | 7 | toolchain + ebpf-guard comm exception | **3.2** |
| confirmed-noisy fim/rootkit daemon writes | 4 | comm+path exception (sshd/cron) | **3.2** |
| confirmed-noisy network, FP<15% | 10 | keep (core detection) | — |
| noisy-only (all) | 58 | exception/disable per rule | **3.2** |
| silent env/input-missing | 110 | keep; document as untested on stend | **3.3** (docs) |
| silent attack-not-attempted | 89 | keep; expand attack suite for замер №2 | **3.3** (test suite) |
| silent condition-not-matched (REVIEW) | 292 | per-rule YAML review; broaden/fix/remove | **3.3** |

**No rule is deleted by this audit.** Every silent rule gets either an environment reason (keep + document) or a `3.3 REVIEW` tag; deletion is a 3.3 decision per rule, after the YAML condition is confirmed dead — exactly as the plan requires ("ни одно не удаляется без явного решения").

## 7. Silent rules — full per-rule list (reason recorded for each)

Grouped by reason code. Within each group the rule id is enough to locate the YAML.

### A — cloud_audit — no cloud provider on stend (keep, verify on cloud) (34)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`aks_managed_identity_token_abuse`</td><td>`cloud_ext_aws_iam_user_created`</td><td>`cloud_ext_gcp_kubernetes_pod_exec`</td></tr>
<tr><td>`cloud_001`</td><td>`cloud_ext_aws_lambda_function_created`</td><td>`cloud_ext_gcp_project_iam_modified`</td></tr>
<tr><td>`cloud_002`</td><td>`cloud_ext_aws_new_access_key`</td><td>`cloud_ext_gcp_service_account_key`</td></tr>
<tr><td>`cloud_003`</td><td>`cloud_ext_aws_root_account_login`</td><td>`cloud_ext_gcp_storage_public`</td></tr>
<tr><td>`cloud_004`</td><td>`cloud_ext_aws_s3_bucket_public`</td><td>`cloud_ext_k8s_cluster_admin_binding`</td></tr>
<tr><td>`cloud_005`</td><td>`cloud_ext_aws_secretsmanager_access`</td><td>`cloud_ext_k8s_privileged_pod`</td></tr>
<tr><td>`cloud_006`</td><td>`cloud_ext_aws_ssm_shell`</td><td>`cloud_ext_k8s_secret_list`</td></tr>
<tr><td>`cloud_007`</td><td>`cloud_ext_azure_keyvault_secret_access`</td><td>`cloud_ext_k8s_webhook_created`</td></tr>
<tr><td>`cloud_ext_aws_cloudtrail_stopped`</td><td>`cloud_ext_azure_rbac_assignment`</td><td>`eks_irsa_unusual_assume_role`</td></tr>
<tr><td>`cloud_ext_aws_ec2_snapshot_copy`</td><td>`cloud_ext_azure_runcommand`</td><td>`gke_service_account_key_creation`</td></tr>
<tr><td>`cloud_ext_aws_guardduty_disabled`</td><td>`cloud_ext_azure_sentinel_disabled`</td><td></td></tr>
<tr><td>`cloud_ext_aws_iam_assume_role_repeated`</td><td>`cloud_ext_azure_storage_anonymous_access`</td><td></td></tr>
</table>

### B — gpu — no GPU on stend (keep, verify on GPU host) (10)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`gpu_alloc_from_unexpected_process`</td><td>`gpu_large_dtoh_copy`</td><td>`gpu_unknown_process`</td></tr>
<tr><td>`gpu_dtoh_from_shell`</td><td>`gpu_medium_dtoh_non_framework`</td><td>`gpu_very_large_dtoh_copy`</td></tr>
<tr><td>`gpu_kernel_launch_from_shell`</td><td>`gpu_mining_pool_connect`</td><td></td></tr>
<tr><td>`gpu_large_compute_burst`</td><td>`gpu_root_dtoh_copy`</td><td></td></tr>
</table>

### C — tls — collector disabled in config (keep, re-enable post-Wave-3) (23)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`appexploit_java_deser_ysoserial`</td><td>`tls_http_basic_auth`</td><td>`tls_ja3_poshc2_default`</td></tr>
<tr><td>`appexploit_php_deser_chain`</td><td>`tls_ja3_any_known_bad_present`</td><td>`tls_ja3_sliver_default`</td></tr>
<tr><td>`cryptominer_stratum_protocol`</td><td>`tls_ja3_brute_ratel`</td><td>`tls_ja3_suspicious_old_tls`</td></tr>
<tr><td>`cryptominer_wallet_address`</td><td>`tls_ja3_cobalt_strike_default`</td><td>`tls_reverse_shell_indicator`</td></tr>
<tr><td>`exfil_large_tls_upload`</td><td>`tls_ja3_cobalt_strike_malleable_common`</td><td>`tls_sql_patterns`</td></tr>
<tr><td>`mitre_http_c2_beacon_pattern`</td><td>`tls_ja3_empire_default`</td><td>`tls_suspicious_user_agent`</td></tr>
<tr><td>`tls_api_key_exposure`</td><td>`tls_ja3_metasploit_default`</td><td>`tls_unexpected_large_transfer`</td></tr>
<tr><td>`tls_data_exfil_patterns`</td><td>`tls_ja3_mythic_default`</td><td></td></tr>
</table>

### D — dns — collector blind on nss-resolve (P0-26) (keep, fixed by Wave 0 on a real DNS scenario) (28)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`appexploit_log4shell_jndi_lookup`</td><td>`dns_suspicious_tld_emercoin`</td><td>`netintr_dga_domain_query`</td></tr>
<tr><td>`c2_paste_site_access`</td><td>`dns_suspicious_tld_onion`</td><td>`netintr_dns_high_digit_ratio`</td></tr>
<tr><td>`cryptominer_dns_pool`</td><td>`dns_txt_suspicious`</td><td>`netintr_dns_high_entropy_query`</td></tr>
<tr><td>`dns_any_query`</td><td>`exfil_dns_deep_subdomain`</td><td>`netintr_dns_many_subdomains`</td></tr>
<tr><td>`dns_dga_high_entropy`</td><td>`exfil_dns_dga_high_score`</td><td>`netintr_dns_over_nonstandard_port`</td></tr>
<tr><td>`dns_dga_ngram`</td><td>`exfil_dns_high_entropy_txt`</td><td>`supply_chain_pkg_dga_dns`</td></tr>
<tr><td>`dns_doh_detected`</td><td>`exfil_dns_high_query_rate`</td><td>`supply_chain_suspicious_registry_dns`</td></tr>
<tr><td>`dns_dynamic_dns`</td><td>`lolbin_dns_exfil_via_dig`</td><td>`webshell_dns_high_entropy`</td></tr>
<tr><td>`dns_nxdomain_flood`</td><td>`mitre_dns_c2_high_frequency`</td><td></td></tr>
<tr><td>`dns_ptr_recon`</td><td>`mitre_ngrok_dns_query`</td><td></td></tr>
</table>

### F — kmod — collector partial (keep, verify with LSM) (8)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`integrity_kernel_module_from_user_path`</td><td>`kmod_load_nonroot`</td><td>`rootkit_kmod_suspicious_name`</td></tr>
<tr><td>`kmod_from_container`</td><td>`kmod_suspicious_name`</td><td>`rootkit_kmod_unsigned_load`</td></tr>
<tr><td>`kmod_load_from_tmpfs`</td><td>`kmod_unexpected_parent`</td><td></td></tr>
</table>

### G — cgroup_esc — needs LSM (keep, verify with LSM) (4)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`container_escape_cgroup_migrate`</td><td>`container_escape_cgroup_v1_release_agent`</td><td></td></tr>
<tr><td>`container_escape_cgroup_to_root`</td><td>`privesc_cgroup_notify_on_release`</td><td></td></tr>
</table>

### J — http_plaintext — no http collector output (keep, investigate collector) (3)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`web_path_traversal_network`</td><td>`web_sql_injection_network`</td><td>`web_xss_network_pattern`</td></tr>
</table>

### H — bpf_subversion — no BPF tampering attempted (keep, add test scenario) (8)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`bpf_activity_unexpected_process`</td><td>`bpf_xdp_tc_unauthorized`</td><td>`rootkit_bpf_map_create_suspicious`</td></tr>
<tr><td>`bpf_kprobe_unauthorized`</td><td>`ebpf_subversion_detach_nonroot`</td><td>`rootkit_bpf_prog_load_suspicious`</td></tr>
<tr><td>`bpf_prog_load_unauthorized`</td><td>`ebpf_subversion_unauthorized_caller`</td><td></td></tr>
</table>

### I — io_uring — not exercised (keep, add test scenario) (3)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`iouring_high_volume_submit`</td><td>`iouring_unexpected_enter`</td><td>`iouring_unexpected_setup`</td></tr>
</table>

### K — privesc — no successful privesc in suite (keep, good; add privesc attack) (8)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`privesc_caps_drop_all`</td><td>`privesc_setuid_gained`</td><td>`privesc_sys_module_gained`</td></tr>
<tr><td>`privesc_net_admin_gained`</td><td>`privesc_sys_admin_gained`</td><td>`privesc_sys_ptrace_gained`</td></tr>
<tr><td>`privesc_net_raw_gained`</td><td>`privesc_sys_chroot_gained`</td><td></td></tr>
</table>

### L — k8s/cloud-k8s — stend is not a k8s node (keep, verify on a real node) (28)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`aks_azure_linux_agent_access`</td><td>`eks_pod_identity_token_read`</td><td>`k8s_hostpath_kubecfg_access`</td></tr>
<tr><td>`aks_bootstrap_kubeconfig_access`</td><td>`fim_kubeconfig_written`</td><td>`k8s_hostpath_kubelet_access`</td></tr>
<tr><td>`aks_imds_access`</td><td>`gke_cloudsql_proxy_socket_access`</td><td>`k8s_kubectl_apiserver_exec`</td></tr>
<tr><td>`aks_service_principal_secret_access`</td><td>`gke_gcloud_credential_access`</td><td>`k8s_metadata_api_access`</td></tr>
<tr><td>`aks_workload_identity_token_read`</td><td>`gke_gcp_sa_json_key_access`</td><td>`k8s_runtime_socket_access`</td></tr>
<tr><td>`eks_aws_config_dir_access`</td><td>`gke_kubelet_readonly_port_access`</td><td>`k8s_sa_token_projected_read`</td></tr>
<tr><td>`eks_aws_credentials_file_read`</td><td>`gke_metadata_server_access`</td><td>`k8s_sa_token_read`</td></tr>
<tr><td>`eks_fargate_task_metadata_access`</td><td>`gke_workload_identity_endpoint_abuse`</td><td>`lateral_kubectl_exec_from_pod`</td></tr>
<tr><td>`eks_imds_credential_theft`</td><td>`k8s_dockerconfig_secret_read`</td><td></td></tr>
<tr><td>`eks_irsa_token_read`</td><td>`k8s_etcd_direct_access`</td><td></td></tr>
</table>

### M — cryptominer — no miner executed (keep, add miner test) (5)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`appexploit_xmrig_download`</td><td>`cryptominer_container_workload`</td><td>`cryptominer_pool_ports`</td></tr>
<tr><td>`cryptominer_binary_name`</td><td>`cryptominer_high_cpu_network`</td><td></td></tr>
</table>

### N — ransomware — no mass-encryption attack (keep, add ransomware test) (9)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`ransomware_backup_delete`</td><td>`ransomware_document_enum`</td><td>`ransomware_mass_rename`</td></tr>
<tr><td>`ransomware_backup_tool_kill`</td><td>`ransomware_encrypted_extension`</td><td>`ransomware_ransom_note`</td></tr>
<tr><td>`ransomware_disk_wipe`</td><td>`ransomware_log_wipe`</td><td>`ransomware_shadow_delete`</td></tr>
</table>

### O — rootkit-deploy — no real rootkit artifact (keep, add rootkit test) (16)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`rootkit_anonymous_exec_memory`</td><td>`rootkit_kexec_load`</td><td>`rootkit_perf_event_open`</td></tr>
<tr><td>`rootkit_delete_module_syscall`</td><td>`rootkit_kmod_from_tmp`</td><td>`rootkit_shared_lib_written_to_system`</td></tr>
<tr><td>`rootkit_hidden_proc_dir`</td><td>`rootkit_large_hidden_file`</td><td>`rootkit_sshd_config_modified`</td></tr>
<tr><td>`rootkit_init_module_syscall`</td><td>`rootkit_ld_library_path_suspicious`</td><td>`rootkit_userfaultfd_create`</td></tr>
<tr><td>`rootkit_kallsyms_read`</td><td>`rootkit_ld_preload_env_set`</td><td></td></tr>
<tr><td>`rootkit_kernel_image_write`</td><td>`rootkit_ld_preload_written`</td><td></td></tr>
</table>

### P — container-escape (file) — escape not attempted + needs LSM (keep, add escape test) (12)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`container_escape_cap_sys_admin`</td><td>`container_escape_crio_socket`</td><td>`container_escape_nsenter`</td></tr>
<tr><td>`container_escape_chroot`</td><td>`container_escape_docker_socket`</td><td>`container_escape_pivot_root`</td></tr>
<tr><td>`container_escape_containerd_socket`</td><td>`container_escape_kmem_access`</td><td>`container_escape_sysrq_trigger`</td></tr>
<tr><td>`container_escape_core_pattern`</td><td>`container_escape_mount`</td><td>`container_escape_unshare_user`</td></tr>
</table>

### Z1 — syscall — condition never matched (REVIEW) (120)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`appexploit_pip_install_malicious`</td><td>`lateral_netcat_socat_pivot`</td><td>`lolbin_tcpdump_write`</td><td>`sigma_chmod_executable_tmp`</td></tr>
<tr><td>`appexploit_shellshock_pattern`</td><td>`lateral_ssh_from_container`</td><td>`lolbin_vim_exec`</td><td>`sigma_iptables_flush`</td></tr>
<tr><td>`appexploit_sqli_exec_xp`</td><td>`lateral_ssh_keygen_new_key`</td><td>`lolbin_wget_download_tmp`</td><td>`sigma_lolbin_awk_shell`</td></tr>
<tr><td>`appexploit_sqli_outfile`</td><td>`lolbin_apt_pre_invoke`</td><td>`lolbin_wget_post_exfil`</td><td>`sigma_lolbin_dd_write`</td></tr>
<tr><td>`appexploit_ssti_pattern`</td><td>`lolbin_bash_dev_tcp`</td><td>`lolbin_zip_exec`</td><td>`sigma_lolbin_env_execution`</td></tr>
<tr><td>`c2_ingress_piped_to_shell`</td><td>`lolbin_bash_dev_udp`</td><td>`mitre_obfusc_base64_payload_large`</td><td>`sigma_lolbin_find_exec`</td></tr>
<tr><td>`c2_raw_socket_shell`</td><td>`lolbin_bash_interactive_shell`</td><td>`mitre_obfusc_char_concatenation`</td><td>`sigma_lolbin_openssl_connect`</td></tr>
<tr><td>`c2_remote_access_tool`</td><td>`lolbin_curl_data_exfil`</td><td>`mitre_obfusc_gzip_payload`</td><td>`sigma_lolbin_python_download`</td></tr>
<tr><td>`cis_5_1_1_cluster_admin_usage`</td><td>`lolbin_dpkg_exec`</td><td>`mitre_obfusc_hex_encoded_exec`</td><td>`sigma_masquerade_kernel_thread`</td></tr>
<tr><td>`cis_5_2_1_privileged_container`</td><td>`lolbin_find_sensitive_recon`</td><td>`mitre_sandbox_detect_cpuid`</td><td>`sigma_memfd_create_anonymous`</td></tr>
<tr><td>`cis_5_2_5_privilege_escalation`</td><td>`lolbin_gdb_exec`</td><td>`mitre_systemd_transient_timer`</td><td>`sigma_mprotect_exec_heap`</td></tr>
<tr><td>`drift_dangerous_syscall`</td><td>`lolbin_git_clone_to_tmp`</td><td>`mitre_vpn_service_started`</td><td>`sigma_perl_shell_execution`</td></tr>
<tr><td>`evasion_auditd_stop`</td><td>`lolbin_ld_audit_set`</td><td>`owasp_web_shell_spawn`</td><td>`sigma_prctl_dumpable`</td></tr>
<tr><td>`evasion_base64_shell_decode`</td><td>`lolbin_less_exec`</td><td>`persist_systemd_wants_symlink`</td><td>`sigma_process_vm_readv`</td></tr>
<tr><td>`evasion_chmod_sensitive`</td><td>`lolbin_lua_exec`</td><td>`persistence_efi_boot_entry_modified`</td><td>`sigma_process_vm_writev`</td></tr>
<tr><td>`evasion_iptables_flush`</td><td>`lolbin_make_exec`</td><td>`privesc_setns_syscall`</td><td>`sigma_ptrace_attach`</td></tr>
<tr><td>`evasion_self_delete`</td><td>`lolbin_nmap_script_exec`</td><td>`privesc_unshare_user_ns`</td><td>`sigma_python_exec_shell`</td></tr>
<tr><td>`evasion_timestamp_modify`</td><td>`lolbin_node_exec`</td><td>`proc_inject_fexecve`</td><td>`sigma_ruby_shell_execution`</td></tr>
<tr><td>`exec_from_tmp`</td><td>`lolbin_path_hijack_indicator`</td><td>`proc_inject_memfd_create`</td><td>`sigma_script_dropper_via_curl`</td></tr>
<tr><td>`execution_dbus_activation_attack`</td><td>`lolbin_perl_socket_shell`</td><td>`proc_inject_ptrace`</td><td>`sigma_seccomp_filter_install`</td></tr>
<tr><td>`exfil_archive_to_network_pipe`</td><td>`lolbin_php_exec_oneliner`</td><td>`ptrace_attach`</td><td>`sigma_setuid_syscall`</td></tr>
<tr><td>`exfil_cloud_sync_tool`</td><td>`lolbin_pip_download_to_tmp`</td><td>`recon_active_connections`</td><td>`sigma_shell_from_unexpected_parent`</td></tr>
<tr><td>`exfil_raw_socket_by_non_root`</td><td>`lolbin_python_socket_shell`</td><td>`recon_network_config`</td><td>`sigma_web_server_shell_spawn`</td></tr>
<tr><td>`impact_fork_bomb_pattern`</td><td>`lolbin_rsync_staging`</td><td>`recon_port_scan_outbound`</td><td>`sigma_world_writable_dir_created`</td></tr>
<tr><td>`impact_systemd_service_disabled`</td><td>`lolbin_ruby_socket_shell`</td><td>`recon_process_enum`</td><td>`web_blind_sqli_heuristic`</td></tr>
<tr><td>`initial_driveby_browser_download_exec`</td><td>`lolbin_scp_download_to_tmp`</td><td>`recon_security_tools_enum`</td><td>`web_sql_injection_command`</td></tr>
<tr><td>`initial_email_link_download_exec`</td><td>`lolbin_sftp_staging`</td><td>`recon_system_info`</td><td>`webshell_command_injection_patterns`</td></tr>
<tr><td>`initial_office_macro_exec`</td><td>`lolbin_socat_shell`</td><td>`recon_user_enum`</td><td>`webshell_java_runtime_exec`</td></tr>
<tr><td>`initial_vpn_unexpected_access`</td><td>`lolbin_tar_exec`</td><td>`sigma_auditd_stopped`</td><td>`webshell_php_disable_functions_bypass`</td></tr>
<tr><td>`integrity_proc_self_exe_exec`</td><td>`lolbin_tclsh_exec`</td><td>`sigma_base64_execution_shell`</td><td>`webshell_php_eval_pattern`</td></tr>
</table>

### Z2 — tcp_connect — dest/port pattern never matched (REVIEW) (43)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`appexploit_java_deser_network_port`</td><td>`drift_new_network_common_c2_ports`</td><td>`netintr_connection_to_multicast`</td><td>`netintr_reverse_shell_port_31337`</td></tr>
<tr><td>`appexploit_log4shell_ldap_port`</td><td>`exfil_ftp_active_connection`</td><td>`netintr_covenant_default_port`</td><td>`netintr_reverse_shell_port_4444`</td></tr>
<tr><td>`appexploit_log4shell_rmi_port`</td><td>`exfil_scp_from_container`</td><td>`netintr_ftp_data_exfil`</td><td>`netintr_smtp_exfil`</td></tr>
<tr><td>`appexploit_ssrf_gcp_metadata`</td><td>`initial_java_jndi_ldap`</td><td>`netintr_gre_tunnel`</td><td>`netintr_socks_proxy_port`</td></tr>
<tr><td>`c2_connect_to_tor_port`</td><td>`initial_ssh_login_new_user`</td><td>`netintr_high_port_established`</td><td>`netintr_vnc_outbound`</td></tr>
<tr><td>`c2_high_port_outbound`</td><td>`initial_trusted_api_pivot`</td><td>`netintr_icmp_outbound_large`</td><td>`owasp_web_metadata_access`</td></tr>
<tr><td>`c2_icmp_large_payload`</td><td>`lateral_port_forward_ssh`</td><td>`netintr_nmap_fingerprint_ports`</td><td>`sigma_irc_c2_ports`</td></tr>
<tr><td>`c2_reverse_shell_standard_ports`</td><td>`lateral_rdp_connection`</td><td>`netintr_outbound_smb`</td><td>`sigma_outbound_tor_ports`</td></tr>
<tr><td>`cloud_ext_aws_imds_v1_access`</td><td>`mitre_winrm_port_connection`</td><td>`netintr_raw_socket_connection`</td><td>`sigma_ssh_many_failed_auth`</td></tr>
<tr><td>`cloud_ext_gcp_compute_metadata_access`</td><td>`netintr_brute_ratel_port`</td><td>`netintr_rdp_outbound`</td><td>`webshell_ssrf_aws_metadata`</td></tr>
<tr><td>`cloud_ext_k8s_etcd_access`</td><td>`netintr_cobalt_strike_default_port`</td><td>`netintr_reverse_shell_port_1234`</td><td></td></tr>
</table>

### Z3 — net_close — timing/size pattern never matched (REVIEW) (5)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`net_long_c2_connection`</td><td>`net_long_plaintext_http`</td><td>`netintr_persistent_c2_beacon`</td></tr>
<tr><td>`net_long_https_connection`</td><td>`net_long_ssh_session`</td><td></td></tr>
</table>

### Z4 — file — watched path/op not touched or comm condition unmet (REVIEW) (124)

<table>
<tr><th>rule</th><th>rule</th><th>rule</th><th>rule</th></tr>
<tr><td>`appexploit_cmd_injection_nc`</td><td>`fim_binary_replaced_in_system_dir`</td><td>`mitre_masq_legitimate_name_in_tmp`</td><td>`persistence_systemd_service_created`</td></tr>
<tr><td>`appexploit_cmd_injection_whoami`</td><td>`fim_ca_cert_modified`</td><td>`mitre_newuidmap_newgidmap`</td><td>`proc_inject_devshm_so`</td></tr>
<tr><td>`appexploit_containerd_socket_access`</td><td>`fim_containerd_config_modified`</td><td>`mitre_ngrok_tunnel`</td><td>`proc_inject_ld_preload_conf`</td></tr>
<tr><td>`appexploit_cri_socket_access`</td><td>`fim_docker_config_modified`</td><td>`mitre_software_enum_dpkg`</td><td>`proc_inject_ld_preload_file`</td></tr>
<tr><td>`appexploit_docker_socket_access`</td><td>`fim_init_d_script_written`</td><td>`mitre_software_enum_security_tools`</td><td>`proc_inject_maps_recon`</td></tr>
<tr><td>`appexploit_lfi_log_poisoning`</td><td>`fim_library_replaced`</td><td>`mitre_ssh_agent_forward_abuse`</td><td>`proc_inject_proc_mem_write`</td></tr>
<tr><td>`appexploit_spring4shell_file_write`</td><td>`fim_network_config_modified`</td><td>`mitre_sslstrip_proxy`</td><td>`recon_sudo_privs`</td></tr>
<tr><td>`appexploit_struts2_ognl_shell`</td><td>`fim_polkit_policy_modified`</td><td>`mitre_token_impersonation_su`</td><td>`sigma_crontab_modification`</td></tr>
<tr><td>`cis_5_1_3_secret_access`</td><td>`fim_private_key_written`</td><td>`mitre_vm_detect_dmi_read`</td><td>`sigma_dev_mem_access`</td></tr>
<tr><td>`collection_direct_db_file_access`</td><td>`fim_rc_local_modified`</td><td>`owasp_backup_config_access`</td><td>`sigma_history_file_cleared`</td></tr>
<tr><td>`collection_local_mail_spool_access`</td><td>`fim_selinux_config_modified`</td><td>`owasp_package_manager_access`</td><td>`sigma_java_child_shell`</td></tr>
<tr><td>`cred_aws_credentials_read`</td><td>`fim_ssh_known_hosts_modified`</td><td>`owasp_php_in_upload`</td><td>`sigma_masquerade_sshd`</td></tr>
<tr><td>`cred_bash_history_read`</td><td>`fim_sudoers_written`</td><td>`owasp_web_suspicious_write`</td><td>`sigma_proc_sysrq_write`</td></tr>
<tr><td>`cred_browser_store_read`</td><td>`fim_syslog_modified`</td><td>`persist_apache_conf_write`</td><td>`sigma_sudo_config_read`</td></tr>
<tr><td>`cred_docker_auth_read`</td><td>`impact_mass_file_deletion_critical`</td><td>`persist_etc_environment_write`</td><td>`sigma_systemd_timer_created`</td></tr>
<tr><td>`cred_gcp_service_account_read`</td><td>`initial_web_shell_write`</td><td>`persist_etc_profile_write`</td><td>`supply_chain_build_tool_rootwrite`</td></tr>
<tr><td>`cred_ssh_private_key_read`</td><td>`integrity_container_runtime_modified`</td><td>`persist_git_hook_write`</td><td>`web_combined_attack`</td></tr>
<tr><td>`cred_vault_token_read`</td><td>`integrity_grub_bootloader_write`</td><td>`persist_profile_d_write`</td><td>`web_file_inclusion_attack`</td></tr>
<tr><td>`credaccess_pam_config_backdoor`</td><td>`integrity_ld_cache_write`</td><td>`persist_sshd_config_write`</td><td>`web_path_traversal_process`</td></tr>
<tr><td>`credaccess_ssh_authorized_keys_modified`</td><td>`integrity_ld_so_preload_write`</td><td>`persist_systemd_path_unit`</td><td>`web_template_injection`</td></tr>
<tr><td>`defense_evasion_binary_truncate_pad`</td><td>`integrity_lib_replaced`</td><td>`persist_systemd_timer_created`</td><td>`web_xss_file_pattern`</td></tr>
<tr><td>`defense_evasion_journald_log_clear`</td><td>`integrity_sysctl_security_disable`</td><td>`persist_xdg_autostart_write`</td><td>`webshell_apache_config_modified`</td></tr>
<tr><td>`evasion_log_clear`</td><td>`lateral_shared_volume_exec`</td><td>`persistence_at_spool_write`</td><td>`webshell_asp_written`</td></tr>
<tr><td>`evasion_system_binary_replace`</td><td>`lateral_ssh_agent_socket_access`</td><td>`persistence_cron_write`</td><td>`webshell_common_filename`</td></tr>
<tr><td>`execution_motd_hook_exec`</td><td>`lolbin_busybox_shell`</td><td>`persistence_etc_init_write`</td><td>`webshell_curl_from_web_proc`</td></tr>
<tr><td>`exfil_clipboard_tool_network`</td><td>`lolbin_strace_exec`</td><td>`persistence_ld_preload_env`</td><td>`webshell_htaccess_modification`</td></tr>
<tr><td>`exfil_usb_mount`</td><td>`mitre_at_job_scheduled`</td><td>`persistence_motd_write`</td><td>`webshell_image_extension_script`</td></tr>
<tr><td>`exfil_wayland_socket_access`</td><td>`mitre_dbus_config_modified`</td><td>`persistence_pam_modified`</td><td>`webshell_jsp_in_web_root`</td></tr>
<tr><td>`exfil_x11_socket_access`</td><td>`mitre_keytab_file_read`</td><td>`persistence_shell_rc_write`</td><td>`webshell_nginx_config_modified`</td></tr>
<tr><td>`fim_apparmor_profile_modified`</td><td>`mitre_krb5_ccache_read`</td><td>`persistence_ssh_authorized_keys`</td><td>`webshell_php_in_web_root`</td></tr>
<tr><td>`fim_audit_rules_modified`</td><td>`mitre_masq_double_extension`</td><td>`persistence_systemd_new_service`</td><td>`webshell_upload_via_image_dir`</td></tr>
</table>

## 8. Reproducibility

Generator: `C:\Users\Honor\AppData\Local\Temp\opencode\rule-audit\` (`audit.py` -> `reasons.py` -> `refine.py`). Re-run after each замер to refresh the table; diffs in the `silent` -> `noisy`/`confirmed` boundary measure whether Wave 3 actually expanded detection coverage vs. only suppressed noise.
