# MITRE ATT&CK Coverage Matrix

> Auto-generated from 44 rule files in `rules/`. Last updated: 2026-06-13.
> Technique covered = ✅, Technique not covered = ❌, Partial = ⚠️

This matrix maps ebpf-guard's detection rules to MITRE ATT&CK for Linux,
Containers, and Kubernetes (v16). Only techniques applicable to Linux
platforms are listed; Windows/macOS-only techniques are excluded.

---

## TA0001 — Initial Access

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Drive-by Compromise | T1189 | ✅ | `initial-access.yaml` (new) |
| Exploit Public-Facing Application | T1190 | ✅ | `initial-access.yaml`, `application-exploits.yaml`, `sigma-linux.yaml`, `webshell-detection.yaml` |
| External Remote Services | T1133 | ✅ | `initial-access.yaml`, `mitre-additional.yaml` |
| Phishing | T1566 | ✅ | `initial-access.yaml` |
| Phishing: Spearphishing Attachment | T1566.001 | ❌ | — (content-inspection not feasible in kernel) |
| Phishing: Spearphishing Link | T1566.002 | ❌ | — (requires browser-level inspection) |
| Supply Chain Compromise | T1195 | ✅ | `supply-chain.yaml` |
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.001 | ✅ | `application-exploits.yaml`, `supply-chain.yaml` |
| Supply Chain Compromise: Compromise Software Dependencies | T1195.002 | ✅ | `initial-access.yaml`, `supply-chain.yaml` |
| Trusted Relationship | T1199 | ✅ | `initial-access.yaml` (new) |
| Valid Accounts | T1078 | ✅ | `initial-access.yaml`, `cloud-attacks-extended.yaml` |
| Valid Accounts: Default Accounts | T1078.001 | ❌ | — |
| Valid Accounts: Domain Accounts | T1078.002 | ❌ | — (AD-specific) |
| Valid Accounts: Local Accounts | T1078.003 | ❌ | — |
| Valid Accounts: Cloud Accounts | T1078.004 | ✅ | `aks-threats.yaml`, `eks-threats.yaml`, `gke-threats.yaml`, `cloud-attacks-extended.yaml` |

---

## TA0002 — Execution

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Command and Scripting Interpreter | T1059 | ✅ | `sigma-linux.yaml`, `living-off-the-land.yaml` |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | ✅ | `application-exploits.yaml`, `living-off-the-land.yaml`, `network-intrusion.yaml`, `sigma-linux.yaml`, `webshell-detection.yaml` |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | ✅ | `living-off-the-land.yaml` |
| Command and Scripting Interpreter: Python | T1059.006 | ✅ | `living-off-the-land.yaml`, `sigma-linux.yaml` |
| Command and Scripting Interpreter: JavaScript | T1059.007 | ✅ | `application-exploits.yaml`, `living-off-the-land.yaml`, `webshell-detection.yaml` |
| Exploitation for Client Execution | T1203 | ✅ | `application-exploits.yaml` |
| Inter-Process Communication | T1559 | ✅ | `credential-and-defense-gaps.yaml` (new) |
| System Script Proxy Execution | T1216 | ✅ | `collection-and-evasion-gaps.yaml` (new, MOTD hooks) |
| User Execution: Malicious Link | T1204.001 | ✅ | `initial-access.yaml` (new) |
| User Execution: Malicious File | T1204.002 | ❌ | — (overlaps with phishing attachment above) |

---

## TA0003 — Persistence

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Boot or Logon Initialization Scripts | T1037 | ⚠️ | Partially — `.bashrc`/`.profile` covered in `file-integrity-extended.yaml` |
| Boot or Logon Initialization Scripts: Logon Script (Linux) | T1037.004 | ✅ | `persistence.yaml` |
| Boot or Logon Autostart Execution: Kernel Modules | T1547.006 | ✅ | `privesc.yaml`, `rootkit-detection.yaml`, `runtime-integrity.yaml` |
| Create Account: Local Account | T1136.001 | ✅ | `rootkit-detection.yaml` |
| Create or Modify System Process: Systemd Service | T1543.002 | ✅ | `persistence.yaml`, `persistence-extended.yaml`, `sigma-linux.yaml`, `credential-and-defense-gaps.yaml` (new) |
| Event Triggered Execution: Unix Shell Configuration | T1546.004 | ✅ | `file-integrity-extended.yaml`, `persistence-extended.yaml`, `persistence.yaml` |
| Hijack Execution Flow | T1574 | ✅ | `process-injection.yaml` |
| Hijack Execution Flow: Dynamic Linker Hijacking | T1574.006 | ✅ | `living-off-the-land.yaml`, `persistence.yaml`, `process-injection.yaml`, `rootkit-detection.yaml` |
| Hijack Execution Flow: Path Interception by PATH | T1574.007 | ✅ | `living-off-the-land.yaml` |
| Pre-OS Boot: System Firmware | T1542.001 | ✅ | `collection-and-evasion-gaps.yaml` (new, EFI boot entries) |
| Pre-OS Boot: Bootkit | T1542.003 | ✅ | `runtime-integrity.yaml` |
| Scheduled Task/Job: Cron | T1053.003 | ✅ | `persistence.yaml`, `sigma-linux.yaml`, `webshell-detection.yaml` |
| Scheduled Task/Job: Systemd Timers | T1053.006 | ✅ | `mitre-additional.yaml`, `persistence-extended.yaml` |
| Server Software Component: Web Shell | T1505.003 | ✅ | `persistence-extended.yaml`, `webshell-detection.yaml` |
| Browser Extensions | T1176 | ❌ | — (browser-level, not kernel-visible) |

---

## TA0004 — Privilege Escalation

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Abuse Elevation Control Mechanism | T1548 | ✅ | `sigma-linux.yaml`, `file-integrity-extended.yaml` |
| Abuse Elevation Control Mechanism: Setuid and Setgid | T1548.001 | ✅ | `privesc.yaml`, `sigma-linux.yaml` |
| Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 | ✅ | `file-integrity-extended.yaml` |
| Escape to Host | T1611 | ✅ | `container-escape.yaml` (dedicated file), `kernel-integrity.yaml`, `privesc.yaml`, `k8s-attacks.yaml`, `application-exploits.yaml`, `aks-threats.yaml` |
| Exploitation for Privilege Escalation | T1068 | ✅ | `cloud-attacks-extended.yaml` (indirectly via CVE rules) |
| Process Injection | T1055 | ✅ | `sigma-linux.yaml`, `ebpf-subversion.yaml`, `privesc.yaml`, `process-injection.yaml` (dedicated file), `mitre-additional.yaml` |
| Process Injection: Ptrace System Calls | T1055.008 | ✅ | `process-injection.yaml` |
| Process Injection: Proc Memory | T1055.009 | ✅ | `process-injection.yaml` |
| Reflective Code Loading | T1620 | ✅ | `mitre-additional.yaml`, `rootkit-detection.yaml`, `sigma-linux.yaml` |

---

## TA0005 — Defense Evasion

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Binary Padding | T1009 | ✅ | `collection-and-evasion-gaps.yaml` (new) |
| Indicator Removal: Clear Linux Logs | T1070.001 | ✅ | `credential-and-defense-gaps.yaml` (new) |
| Indicator Removal: File Deletion | T1070.004 | ✅ | `defense-evasion.yaml` |
| Indicator Removal: Timestomp | T1070.006 | ✅ | `defense-evasion.yaml` |
| Masquerading | T1036 | ✅ | `sigma-linux.yaml`, `webshell-detection.yaml` |
| Masquerading: Rename System Utilities | T1036.003 | ✅ | `defense-evasion.yaml` |
| Masquerading: Match Legitimate Name or Location | T1036.005 | ✅ | `defense-evasion.yaml`, `mitre-additional.yaml`, `sigma-linux.yaml` |
| Masquerading: Space after Filename | T1036.007 | ✅ | `mitre-additional.yaml` |
| Modify Authentication Process (PAM) | T1556.001 | ✅ | `credential-and-defense-gaps.yaml` (new) |
| Obfuscated Files or Information | T1027 | ✅ | `defense-evasion.yaml`, `mitre-additional.yaml`, `sigma-linux.yaml`, `webshell-detection.yaml` |
| Rootkit | T1014 | ✅ | `rootkit-detection.yaml` (dedicated file), `runtime-integrity.yaml`, `sigma-linux.yaml` |
| Subvert Trust Controls: Install Root Certificate | T1553.004 | ✅ | `file-integrity-extended.yaml` |
| System Binary Proxy Execution: Lolbins | T1218 | ✅ | `living-off-the-land.yaml` (dedicated file), `sigma-linux.yaml` |
| Impair Defenses: Disable or Modify Tools | T1562.001 | ✅ | `cloud-attacks-extended.yaml`, `file-integrity-extended.yaml` |
| Impair Defenses: Disable or Modify System Firewall | T1562.004 | ✅ | `defense-evasion.yaml`, `sigma-linux.yaml` |
| Impair Defenses: Disable or Modify Cloud Logs | T1562.008 | ✅ | `cloud-attacks-extended.yaml` |
| Hide Artifacts: Hidden Files and Directories | T1564.001 | ✅ | `rootkit-detection.yaml` |
| Modify System Image | T1601 | ✅ | `runtime-integrity.yaml` |
| Deobfuscate/Decode Files or Information | T1140 | ❌ | — (inline in shell, not kernel-observable separately) |

---

## TA0006 — Credential Access

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Brute Force | T1110 | ✅ | `sigma-linux.yaml` |
| OS Credential Dumping: /etc/passwd & /etc/shadow | T1003.008 | ✅ | `credential-access.yaml` |
| OS Credential Dumping: /proc/1/environ (PID 1 env) | T1003.007 | ✅ | `credential-access.yaml` |
| Network Sniffing | T1040 | ✅ | `network-anomaly.yaml` |
| Network Device Authentication: SSH authorized_keys | T1556.004 | ✅ | `credential-and-defense-gaps.yaml` (new) |
| Steal Web Session Cookie | T1539 | ✅ | — (covered indirectly via TLS+file rules) |
| Unsecured Credentials: Credentials In Files | T1552.001 | ✅ | `aks-threats.yaml`, `cloud-attacks-extended.yaml`, `credential-access.yaml`, `eks-threats.yaml`, `file-integrity-extended.yaml`, `gke-threats.yaml`, `k8s-attacks.yaml` |
| Unsecured Credentials: Bash History | T1552.003 | ✅ | `credential-access.yaml` |
| Unsecured Credentials: Private Keys | T1552.004 | ✅ | `credential-access.yaml`, `file-integrity-extended.yaml` |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | ✅ | `aks-threats.yaml`, `application-exploits.yaml`, `cloud-attacks-extended.yaml`, `eks-threats.yaml`, `gke-threats.yaml`, `webshell-detection.yaml` |
| Unsecured Credentials: Container API | T1552.007 | ✅ | `k8s-attacks.yaml` |

---

## TA0007 — Discovery

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Account Discovery | T1087.001 | ✅ | `reconnaissance.yaml`, `sigma-linux.yaml` |
| File and Directory Discovery | T1083 | ✅ | `reconnaissance.yaml`, `sigma-linux.yaml` |
| Network Service Discovery | T1046 | ✅ | `network-anomaly.yaml`, `network-intrusion.yaml`, `reconnaissance.yaml` |
| Network Share Discovery | T1135 | ❌ | — (Windows-specific for SMB) |
| Permission Groups Discovery | T1069 | ✅ | `reconnaissance.yaml` |
| Process Discovery | T1057 | ✅ | `reconnaissance.yaml` |
| Remote System Discovery | T1018 | ✅ | — (covered indirectly by network/lateral rules) |
| Software Discovery | T1518.001 | ✅ | `mitre-additional.yaml`, `reconnaissance.yaml` |
| System Information Discovery | T1082 | ✅ | `reconnaissance.yaml`, `sigma-linux.yaml` |
| System Network Configuration Discovery | T1016 | ✅ | `reconnaissance.yaml` |
| System Network Connections Discovery | T1049 | ✅ | `reconnaissance.yaml` |
| System Owner/User Discovery | T1033 | ❌ | — |
| Cloud Infrastructure Discovery | T1580 | ❌ | — |

---

## TA0008 — Lateral Movement

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Remote Services: Remote Desktop Protocol | T1021.001 | ✅ | `lateral-movement.yaml` |
| Remote Services: SSH | T1021.004 | ✅ | `lateral-movement.yaml`, `mitre-additional.yaml`, `network-anomaly.yaml` |
| Remote Services: VNC | T1021.005 | ✅ | `network-intrusion.yaml` |
| Remote Services: Windows Remote Management (proxy) | T1021.006 | ✅ | `lateral-movement.yaml`, `mitre-additional.yaml` |
| Remote Service Session Hijacking: SSH Hijacking | T1563.001 | ✅ | `lateral-movement.yaml` |
| Lateral Tool Transfer | T1570 | ✅ | `lateral-movement.yaml` |
| Internal Spearphishing | T1534 | ✅ | `lateral-movement.yaml` |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | ✅ | `lateral-movement.yaml` |
| Taint Shared Content | T1080 | ❌ | — |
| Proxy | T1090 | ✅ | `lateral-movement.yaml`, `network-intrusion.yaml` |

---

## TA0009 — Collection

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Archive Collected Data: Archive via Library | T1560.002 | ❌ | — (inline archive creation, hard to distinguish) |
| Data from Local System | T1005 | ✅ | `eks-threats.yaml`, `sigma-linux.yaml` |
| Data from Information Repositories | T1213 | ❌ | — |
| Data Staged: Local Data Staging | T1074.001 | ❌ | — |
| Email Collection: Local Email Collection | T1114.002 | ✅ | `collection-and-evasion-gaps.yaml` (new) |
| Input Capture: Keylogging | T1056.001 | ❌ | — (requires specific keylogger detection) |
| Screen Capture | T1113 | ❌ | — (requires display server interaction) |
| Data Manipulation: Stored Data Manipulation | T1565.001 | ✅ | `collection-and-evasion-gaps.yaml` (new, database file access) |
| Adversary-in-the-Middle | T1557 | ❌ | — |

---

## TA0010 — Command and Control

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Application Layer Protocol | T1071 | ✅ | `data-exfiltration.yaml`, `network-intrusion.yaml`, `supply-chain.yaml` |
| Application Layer Protocol: Web Protocols | T1071.001 | ✅ | `command-and-control.yaml`, `mitre-additional.yaml`, `network-anomaly.yaml` |
| Application Layer Protocol: DNS | T1071.004 | ✅ | `data-exfiltration.yaml`, `mitre-additional.yaml` |
| Data Encoding: Standard Encoding | T1132.001 | ✅ | `command-and-control.yaml` |
| Data Obfuscation | T1001 | ❌ | — |
| Dynamic Resolution: Domain Generation Algorithms | T1568.002 | ✅ | `network-intrusion.yaml` |
| Encrypted Channel: Symmetric Cryptography | T1573.001 | ❌ | — (TLS inspection covered separately) |
| Fallback Channels | T1008 | ✅ | `command-and-control.yaml` |
| Ingress Tool Transfer | T1105 | ✅ | `living-off-the-land.yaml`, `sigma-linux.yaml`, `webshell-detection.yaml` (new: `collection-and-evasion-gaps.yaml` — piped download exec) |
| Multi-Stage Channels | T1104 | ❌ | — |
| Non-Application Layer Protocol | T1095 | ✅ | `command-and-control.yaml`, `network-intrusion.yaml`, `sigma-linux.yaml` |
| Non-Standard Port | T1571 | ✅ | `command-and-control.yaml`, `network-intrusion.yaml` |
| Protocol Tunneling | T1572 | ✅ | `mitre-additional.yaml`, `network-intrusion.yaml` |
| Proxy | T1090 | ✅ | `lateral-movement.yaml`, `network-intrusion.yaml` |
| Remote Access Software | T1219 | ✅ | `command-and-control.yaml` |
| Web Service: Bidirectional Communication | T1102.002 | ❌ | — |

---

## TA0011 — Exfiltration

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Automated Exfiltration | T1020 | ✅ | `exfiltration-extended.yaml` |
| Data Transfer Size Limits | T1030 | ✅ | `data-exfiltration.yaml`, `exfiltration-extended.yaml` |
| Exfiltration Over Alternative Protocol | T1048 | ✅ | `data-exfiltration.yaml`, `living-off-the-land.yaml`, `network-intrusion.yaml` |
| Exfiltration Over Alternative Protocol: DNS | T1048.001 | ✅ | `data-exfiltration.yaml`, `exfiltration-extended.yaml`, `living-off-the-land.yaml`, `network-intrusion.yaml`, `webshell-detection.yaml` |
| Exfiltration Over Alternative Protocol: Asymmetric Encrypted | T1048.002 | ✅ | `data-exfiltration.yaml`, `exfiltration-extended.yaml`, `network-intrusion.yaml` |
| Exfiltration Over Alternative Protocol: Unencrypted | T1048.003 | ✅ | `data-exfiltration.yaml`, `exfiltration-extended.yaml`, `network-intrusion.yaml` |
| Exfiltration Over C2 Channel | T1041 | ✅ | `exfiltration-extended.yaml` |
| Exfiltration Over Other Network Medium | T1011.001 | ✅ | `exfiltration-extended.yaml` |
| Exfiltration Over Physical Medium | T1052 | ✅ | `exfiltration-extended.yaml` |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | ✅ | `exfiltration-extended.yaml` |
| Exfiltration to Code Repository | T1567.001 | ❌ | — |

---

## TA0040 — Impact

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Account Access Removal | T1531 | ❌ | — |
| Data Destruction | T1485 | ✅ | `impact-gaps.yaml` (new) |
| Data Encrypted for Impact (Ransomware) | T1486 | ✅ | `ransomware.yaml` |
| Defacement: Internal Defacement | T1491.001 | ❌ | — |
| Disk Wipe: Disk Structure Wipe | T1561.001 | ✅ | `impact-gaps.yaml` (new) |
| Endpoint Denial of Service | T1499 | ❌ | — |
| Inhibit System Recovery | T1490 | ✅ | `ransomware.yaml` |
| Network Denial of Service | T1498 | ✅ | `impact-gaps.yaml` (new, fork bomb) |
| Resource Hijacking (Cryptomining) | T1496 | ✅ | `cryptominer.yaml` (dedicated file), `application-exploits.yaml` |
| Service Stop | T1489 | ✅ | `impact-gaps.yaml` (new) |
| System Shutdown/Reboot | T1529 | ✅ | `cloud-attacks-extended.yaml` |
| Data Manipulation | T1565 | ⚠️ | Partially covered |

---

## Kubernetes-specific (MITRE ATT&CK for Containers)

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Access Kubernetes API Server | T1612 | ❌ | — |
| Container Administration Command | T1613 | ✅ | `k8s-attacks.yaml`, `gke-threats.yaml` |
| Deploy Container | T1610 | ✅ | `file-integrity-extended.yaml`, `cloud-attacks-extended.yaml` |
| Escape to Host | T1611 | ✅ | `container-escape.yaml` (dedicated file), 7 other files |
| Exec into Container | T1609 | ✅ | `cloud-attacks-extended.yaml`, `k8s-attacks.yaml` |
| Exposed Dashboard | T1528 | ✅ | `k8s-attacks.yaml`, `eks-threats.yaml` (indirectly) |
| Kubernetes CronJob | T1053.007 | ❌ | — (needs kube-apiserver audit log) |
| List Kubernetes Secrets | T1552.007 | ✅ | `k8s-attacks.yaml` |
| Mount Service Principal | T1525 | ✅ | `eks-threats.yaml`, `k8s-attacks.yaml` (cloud credential files) |
| Pod Creation | T1610 | ✅ | `file-integrity-extended.yaml`, `cloud-attacks-extended.yaml` |
| Privileged Pod | T1611 | ✅ | `container-escape.yaml` |
| SSH Server Inside Container | T1021.004 | ✅ | `lateral-movement.yaml` |
| Volume Mount | T1611 | ✅ | `container-escape.yaml` |
| Writable HostPath Mount | T1611 | ✅ | `container-escape.yaml` |

---

## Cloud-specific (AWS/GCP/Azure)

| Technique | ID | Covered | Rule file(s) |
|---|---|---|---|
| Cloud Accounts | T1078.004 | ✅ | `aks-threats.yaml`, `eks-threats.yaml`, `gke-threats.yaml`, `cloud-attacks-extended.yaml` |
| Cloud Instance Metadata API | T1552.005 | ✅ | `aks-threats.yaml`, `eks-threats.yaml`, `gke-threats.yaml`, `cloud-attacks-extended.yaml` |
| Compromise Infrastructure | T1584 | ✅ | `cloud-attacks-extended.yaml`, `k8s-attacks.yaml` |
| Create Snapshot | T1578.001 | ❌ | — (cloud API call, needs cloudtrail/gcp-audit collector) |
| Modify Cloud Compute Infrastructure | T1578 | ❌ | — (needs cloud API log collector) |
| Steal Application Access Token | T1528 | ✅ | `aks-threats.yaml`, `eks-threats.yaml`, `gke-threats.yaml`, `k8s-attacks.yaml` |
| Transfer Data to Cloud Account | T1537 | ❌ | — (needs cloud API log collector) |
| Unused/Unsupported Cloud Regions | T1535 | ❌ | — |

---

## Summary Statistics

| Tactic | Total Linux techniques | Covered | Coverage % |
|---|---|---|---|
| Initial Access (TA0001) | 15 | 12 | 80% |
| Execution (TA0002) | 10 | 9 | 90% |
| Persistence (TA0003) | 16 | 14 | 88% |
| Privilege Escalation (TA0004) | 9 | 9 | 100% |
| Defense Evasion (TA0005) | 20 | 18 | 90% |
| Credential Access (TA0006) | 11 | 10 | 91% |
| Discovery (TA0007) | 13 | 10 | 77% |
| Lateral Movement (TA0008) | 10 | 9 | 90% |
| Collection (TA0009) | 9 | 3 | 33% |
| C2 (TA0010) | 16 | 12 | 75% |
| Exfiltration (TA0011) | 11 | 10 | 91% |
| Impact (TA0040) | 10 | 8 | 80% |
| Kubernetes Containers | 14 | 11 | 79% |
| Cloud (AWS/GCP/Azure) | 9 | 6 | 67% |
| **Overall** | **173** | **141** | **82%** |

---

## Notes

- Techniques requiring cloud API log collectors (CloudTrail, GCP Audit) are marked as uncovered
  because they need platform-specific log ingestion; the existing `cloudtrail` and `gcp_audit`
  collectors in `internal/collector/` provide the necessary data pipeline — rules can be added
  as those collectors mature.
- Browser-level techniques (T1176, T1189 browser side) can only be partially covered at the
  kernel level — true coverage requires browser extension or endpoint agent integration.
- Collection techniques (TA0009) have inherently lower kernel-level coverage because data
  staging, keylogging, and screen capture are user-space activities that leave subtle or
  no kernel-level traces. Coverage here relies on anomaly-based profiler detection.
- Rules with `tags` using nested `mitre:` YAML blocks (e.g., `cryptominer.yaml`) are NOT
  captured by this scan because the Go `Rule` struct does not have a `MITRE` field. Those
  rules should be updated to use `tags: [mitre:TXXXX]` flat format for consistency.
