#!/usr/bin/env python3
"""Generate MITRE ATT&CK coverage report from ebpf-guard rule files.

Usage:
    python3 scripts/mitre-coverage.py --rules-dir rules/ --output report.md
    python3 scripts/mitre-coverage.py --rules-dir rules/ --count-only
"""

import argparse
import glob
import re
import sys
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("pyyaml not installed — run: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)

# MITRE ATT&CK technique descriptions (subset of Linux-relevant techniques)
TECHNIQUE_NAMES = {
    "T1001": "Data Obfuscation",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1014": "Rootkit",
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH",
    "T1021.005": "VNC",
    "T1021.006": "Windows Remote Management",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1036.005": "Match Legitimate Name or Location",
    "T1036.007": "Double File Extension",
    "T1040": "Network Sniffing",
    "T1046": "Network Service Discovery",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.001": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
    "T1048.002": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
    "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
    "T1053": "Scheduled Task/Job",
    "T1053.001": "At",
    "T1053.003": "Cron",
    "T1053.006": "Systemd Timers",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Unix Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1059.007": "JavaScript",
    "T1070": "Indicator Removal",
    "T1070.002": "Clear Linux or Mac System Logs",
    "T1070.003": "Clear Command History",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1078": "Valid Accounts",
    "T1078.004": "Cloud Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1087.001": "Local Account",
    "T1090": "Proxy",
    "T1090.003": "Multi-hop Proxy",
    "T1095": "Non-Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1098.004": "SSH Authorized Keys",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1112": "Modify Registry",
    "T1133": "External Remote Services",
    "T1134": "Access Token Manipulation",
    "T1136": "Create Account",
    "T1136.001": "Local Account",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1195.001": "Compromise Software Dependencies and Development Tools",
    "T1203": "Exploitation for Client Execution",
    "T1210": "Exploitation of Remote Services",
    "T1218": "System Binary Proxy Execution",
    "T1222": "File and Directory Permissions Modification",
    "T1484": "Domain Policy Modification",
    "T1496": "Resource Hijacking",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1497.001": "System Checks",
    "T1505": "Server Software Component",
    "T1505.003": "Web Shell",
    "T1518": "Software Discovery",
    "T1518.001": "Security Software Discovery",
    "T1530": "Data from Cloud Storage",
    "T1537": "Transfer Data to Cloud Account",
    "T1543": "Create or Modify System Process",
    "T1543.002": "Systemd Service",
    "T1546": "Event Triggered Execution",
    "T1546.004": "Unix Shell Configuration Modification",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.006": "Kernel Modules and Extensions",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.001": "Setuid and Setgid",
    "T1548.002": "Bypass User Account Control",
    "T1548.003": "Sudo and Sudo Caching",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1552.004": "Private Keys",
    "T1552.005": "Cloud Instance Metadata API",
    "T1553": "Subvert Trust Controls",
    "T1553.004": "Install Root Certificate",
    "T1556": "Modify Authentication Process",
    "T1556.003": "Pluggable Authentication Modules",
    "T1557": "Adversary-in-the-Middle",
    "T1557.002": "ARP Cache Poisoning",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.004": "Disable or Modify System Firewall",
    "T1562.008": "Disable or Modify Cloud Logs",
    "T1564": "Hide Artifacts",
    "T1564.001": "Hidden Files and Directories",
    "T1565": "Data Manipulation",
    "T1565.001": "Stored Data Manipulation",
    "T1568": "Dynamic Resolution",
    "T1568.002": "Domain Generation Algorithms",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    "T1574": "Hijack Execution Flow",
    "T1574.006": "Dynamic Linker Hijacking",
    "T1574.007": "Path Interception by PATH Environment Variable",
    "T1580": "Cloud Infrastructure Discovery",
    "T1583": "Acquire Infrastructure",
    "T1584": "Compromise Infrastructure",
    "T1609": "Container Administration Command",
    "T1610": "Deploy Container",
    "T1611": "Escape to Host",
    "T1620": "Reflective Code Loading",
}

TAG_PATTERN = re.compile(r"mitre:(T\d{4}(?:\.\d{3})?)")


def load_rules(rules_dir: str) -> list[dict]:
    rules = []
    for path in sorted(glob.glob(f"{rules_dir}/*.yaml")):
        with open(path) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"Warning: YAML error in {path}: {e}", file=sys.stderr)
                continue
        if not data or "rules" not in data:
            continue
        for rule in data.get("rules") or []:
            rule["_source_file"] = path
            rules.append(rule)
    return rules


def extract_techniques(rules: list[dict]) -> dict[str, list[dict]]:
    technique_rules: dict[str, list[dict]] = defaultdict(list)
    for rule in rules:
        tags = rule.get("tags") or []
        for tag in tags:
            matches = TAG_PATTERN.findall(str(tag))
            for tech in matches:
                technique_rules[tech].append(rule)
    return technique_rules


def generate_report(rules: list[dict], technique_rules: dict[str, list[dict]]) -> str:
    lines = [
        "# MITRE ATT&CK Coverage Report",
        "",
        f"**Total rules:** {len(rules)}  ",
        f"**Techniques covered:** {len(technique_rules)}  ",
        f"**Total technique mappings:** {sum(len(v) for v in technique_rules.values())}",
        "",
        "## Coverage Matrix",
        "",
        "| Technique | Name | Rule Count | Rules |",
        "|-----------|------|-----------|-------|",
    ]

    for tech_id in sorted(technique_rules.keys()):
        tech_rules = technique_rules[tech_id]
        name = TECHNIQUE_NAMES.get(tech_id, "—")
        rule_list = ", ".join(r.get("id", "?") for r in tech_rules[:5])
        if len(tech_rules) > 5:
            rule_list += f" (+{len(tech_rules) - 5} more)"
        lines.append(f"| [{tech_id}](https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}) | {name} | {len(tech_rules)} | {rule_list} |")

    # Rules without MITRE tags
    untagged = [r for r in rules if not any(
        TAG_PATTERN.search(str(t)) for t in (r.get("tags") or [])
    )]

    lines += [
        "",
        "## Coverage by Tactic",
        "",
    ]

    tactic_map = {
        "TA0001": ("Initial Access", ["T1190", "T1133", "T1195"]),
        "TA0002": ("Execution", ["T1059", "T1203", "T1053", "T1609"]),
        "TA0003": ("Persistence", ["T1543", "T1546", "T1547", "T1505", "T1098"]),
        "TA0004": ("Privilege Escalation", ["T1548", "T1611", "T1134"]),
        "TA0005": ("Defense Evasion", ["T1027", "T1036", "T1070", "T1562", "T1497", "T1620"]),
        "TA0006": ("Credential Access", ["T1003", "T1040", "T1110", "T1552", "T1558", "T1557"]),
        "TA0007": ("Discovery", ["T1046", "T1082", "T1083", "T1087", "T1518", "T1580"]),
        "TA0008": ("Lateral Movement", ["T1021", "T1210"]),
        "TA0009": ("Collection", ["T1530"]),
        "TA0010": ("Exfiltration", ["T1048", "T1537"]),
        "TA0011": ("Command and Control", ["T1071", "T1090", "T1095", "T1572", "T1568", "T1571"]),
        "TA0040": ("Impact", ["T1496", "T1565"]),
    }

    for tactic_id, (tactic_name, techniques) in tactic_map.items():
        covered = [t for t in techniques if any(
            tech.startswith(t) for tech in technique_rules
        )]
        pct = int(100 * len(covered) / len(techniques)) if techniques else 0
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        lines.append(f"**{tactic_name}** ({tactic_id}): [{bar}] {pct}%  ")
        lines.append(f"  Techniques with rules: {', '.join(covered) if covered else '—'}")
        lines.append("")

    lines += [
        "",
        f"## Untagged Rules ({len(untagged)})",
        "",
        "Rules without MITRE ATT&CK technique tags:",
        "",
    ]
    for rule in untagged[:20]:
        lines.append(f"- `{rule.get('id', '?')}` — {rule.get('name', '?')}")
    if len(untagged) > 20:
        lines.append(f"- ... and {len(untagged) - 20} more")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate MITRE ATT&CK coverage report")
    parser.add_argument("--rules-dir", default="rules/", help="Directory containing rule YAML files")
    parser.add_argument("--output", help="Output markdown file path (default: stdout)")
    parser.add_argument("--count-only", action="store_true", help="Print technique count only")
    args = parser.parse_args()

    rules = load_rules(args.rules_dir)
    technique_rules = extract_techniques(rules)

    if args.count_only:
        print(len(technique_rules))
        return 0

    report = generate_report(rules, technique_rules)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
