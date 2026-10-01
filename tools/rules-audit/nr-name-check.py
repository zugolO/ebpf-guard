#!/usr/bin/env python3
"""Syscall numbers in rules/*.yaml against the names their own comments give them.

Finding №519 (01.10.2026) came from reading conditions, not from a run:

  evasion_auditd_stop       ["62","37","238"]  # kill, tkill, tgkill   (37 = alarm, 238 = set_mempolicy)
  web_blind_sqli_heuristic  ["35","206","162"] # nanosleep, clock_nanosleep, select   (206 = io_setup, 162 = sync)
  mitre_sandbox_detect_cpuid nr 135 "arch_prctl"                      (135 = personality; arch_prctl is 158)

A rule that names the wrong number is MUTE or FIRES ON THE WRONG CALL for the whole
life of the rule, and no run notices: the number is in the allowlist, events arrive,
the condition matches something else. This tool lists every `values:` line on an
`nr`/`syscall.nr` condition whose trailing comment names syscalls, and compares each
named syscall to the number at the same position, against the authoritative x86_64
table (golang.org/x/sys/unix zsysnum_linux_amd64.go, read from the module cache — no
hand-typed table that could carry the same mistake).

Exit code 1 if a mismatch is found, so it can sit in a pre-commit or CI step.

    python3 tools/rules-audit/nr-name-check.py            # all rules/*.yaml
    python3 tools/rules-audit/nr-name-check.py --json
"""
import glob
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def syscall_table():
    mod = subprocess.check_output(["go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys"],
                                  cwd=REPO).decode().strip()
    by_nr = {}
    with open(os.path.join(mod, "unix", "zsysnum_linux_amd64.go"), encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\s*SYS_([A-Z0-9_]+)\s*=\s*(\d+)", line)
            if m:
                by_nr.setdefault(int(m.group(2)), []).append(m.group(1).lower())
    return by_nr


FIELD = re.compile(r"^\s*-\s*field:\s*(?:syscall\.)?nr\b")
VALUES = re.compile(r"^\s*values:\s*\[(?P<vals>[^\]]*)\]\s*(?:#\s*(?P<c>.*))?$")
RULE_ID = re.compile(r"^\s*-\s*id:\s*(\S+)")


def scan(path, table):
    out, rule = [], "?"
    lines = open(path, encoding="utf-8").read().splitlines()
    for i, line in enumerate(lines):
        m = RULE_ID.match(line)
        if m:
            rule = m.group(1).strip('"')
        if not FIELD.match(line):
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            v = VALUES.match(lines[j])
            if not v:
                continue
            nums = [int(x) for x in re.findall(r"\d+", v.group("vals"))]
            comment = re.sub(r"\(.*?\)", "", v.group("c") or "")   # «select (sleep syscalls)» -> «select»
            comment = re.split(r"\s[—-]\s", comment)[0]              # «name — prose» -> «name»
            names = [re.sub(r"^_*nr_+", "", n.strip().lower()) for n in re.split(r"[,/]", comment) if n.strip()]
            # only comments that are a plain list of names are checked: prose in a comment
            # is not a claim about a position. One number with several aliases
            # («execveat / fexecve») is checked as «any alias matches».
            if names and all(re.fullmatch(r"[a-z0-9_]+", n) for n in names):
                if len(names) == len(nums):
                    pairs = list(zip(nums, [[n] for n in names]))
                elif len(nums) == 1:
                    pairs = [(nums[0], names)]
                else:
                    pairs = []
                for nr, claimed in pairs:
                    if nr >= 512:       # x32 ABI numbers (0x40000000 | n is not in the amd64 table)
                        continue
                    real = table.get(nr, ["?"])
                    if not any(c in real for c in claimed):
                        out.append({"rule": rule, "file": os.path.basename(path), "line": j + 1,
                                    "nr": nr, "comment_says": "/".join(claimed), "table_says": real[0]})
            break
    return out


def main():
    table = syscall_table()
    found = []
    for path in sorted(glob.glob(os.path.join(REPO, "rules", "*.yaml"))):
        found += scan(path, table)
    if "--json" in sys.argv:
        print(json.dumps(found, ensure_ascii=False, indent=1))
    else:
        for f in found:
            print("%-40s %s:%d  nr=%-4d комментарий «%s», таблица x86_64 «%s»"
                  % (f["rule"], f["file"], f["line"], f["nr"], f["comment_says"], f["table_says"]))
        print("итого расхождений номера и названного имени: %d" % len(found))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
