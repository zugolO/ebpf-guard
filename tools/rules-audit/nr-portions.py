#!/usr/bin/env python3
"""Wave 7 item б3 — the portion manifest for opening the `nr` axis.

Item б2 measured, on ebaka2 with bpftrace, what each of the 19 syscall numbers
named by the 12 structurally mute `nr` rules costs per minute on an idle node
(server-logs/w7-syscall-price-2026-09-29/). Item б3 opens them in portions,
cheapest first, and judges every portion by an A/B pair.

This writes the manifest the pipeline reads:

    deploy/docker-test-setup/attacks/wave7-nr-portions.txt

The rule membership of a portion is NOT written by hand: it is derived from the
REAL ruleset (via `go run ./tools/rules-audit`, the extractor classify.py uses),
by the same predicate the product's RuleEngine.UnreachableSyscallRules applies.
A rule opens as soon as ANY of its numbers is open, so it belongs to the FIRST
portion that contains one of them — the portion whose price buys it.

The audit CSV was the first source here and was WRONG for this purpose: it
covers the 292 rules revision 3.0 listed, and eight `nr`-mute rules live outside
that list (finding of the drift guard below, 29.09.2026). A manifest built from
it claimed portion 3 buys 3 rules where the ruleset says 4.

Reproduce (from the repo root, no network, no stand):

    python3 tools/rules-audit/nr-portions.py

TestWave7PortionManifestMatchesRuleset (internal/correlator) is the drift guard:
it replays each portion against the real ruleset through
RuleEngine.UnreachableSyscallRules and fails if the rules named here are not
exactly the rules that stop being mute.
"""
import json
import os
import subprocess
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_DIR = os.path.join(REPO, "rules")
OUT = os.path.join(REPO, "deploy", "docker-test-setup", "attacks", "wave7-nr-portions.txt")

# The baseline the audit's "12 structurally mute rules" was computed against:
# internal/bpf.DefaultMonitoredSyscalls(). config-test.yaml on the stand sets no
# monitored_syscalls and falls back to exactly this list.
BASELINE = [59, 322, 101, 126, 308, 272, 319, 165, 166, 155, 161, 311, 310, 298,
            175, 313, 176, 321, 105]

# Portions in the order item б3 opens them, cheapest first. The price is the
# measured one (calls/min on the idle node, item б2), not an estimate.
PORTIONS = [
    ("1", "нулевая", [57, 132, 135, 162, 206, 235, 238, 258, 280, 317]),
    ("2", "дешёвая", [88, 37, 83, 157, 62]),
    ("3", "дорогая", [56, 41, 10]),
]

# Measured calls/min per number, server-logs/w7-syscall-price-2026-09-29/.
PRICE = {57: 0, 132: 0, 135: 0, 162: 0, 206: 0, 235: 0, 238: 0, 258: 0, 280: 0,
         317: 0, 88: 3, 37: 30, 83: 37, 157: 50, 62: 61, 56: 198, 41: 505,
         10: 1668, 35: 22775}

# Named and NOT opened: 22 775 calls/min of node share, and the only rule that
# depends on it (web_blind_sqli_heuristic) already opens for free via sync(162).
EXCLUDED = {35: "22 775/мин доли ноды; web_blind_sqli_heuristic открывается через sync(162) даром"}

NAMES = {10: "mprotect", 35: "nanosleep", 37: "alarm", 41: "socket", 56: "clone",
         57: "fork", 62: "kill", 83: "mkdir", 88: "symlink", 132: "utime",
         135: "personality", 157: "prctl", 162: "sync", 206: "io_setup",
         235: "utimes", 238: "set_mempolicy", 258: "mkdirat", 280: "utimensat",
         317: "seccomp"}


def mute_rules_by_number():
    """{rule_id: sorted nr values} for every syscall rule whose numeric `nr`
    set misses the baseline entirely — the product's UnreachableSyscallRules
    predicate, applied to the extractor's dump of the real ruleset."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    try:
        subprocess.run(["go", "run", "./tools/rules-audit", RULES_DIR, out],
                       cwd=REPO, check=True)
        with open(out, encoding="utf-8") as fh:
            dump = json.load(fh)
    finally:
        os.unlink(out)

    baseline = set(BASELINE)
    found = {}
    for rid, rule in dump.items():
        if rule.get("event_type") != "syscall":
            continue
        nums = set()
        for cond in walk_conditions(rule):
            # namesLiteralValues(cond, "nr"): dotted alias normalised, and the
            # three operators that name literal values.
            if (cond.get("field") or "").replace("syscall.", "") != "nr":
                continue
            if cond.get("op") not in ("in", "equals", "eq"):
                continue
            for value in cond.get("values") or []:
                try:
                    nums.add(int(str(value).strip()))
                except ValueError:
                    continue
        if nums and not (nums & baseline):
            found[rid] = sorted(nums)
    return found


def walk_conditions(rule):
    out = []
    if rule.get("condition"):
        out.append(rule["condition"])
    out.extend(rule.get("conditions") or [])

    def walk(group):
        if not group:
            return
        out.extend(group.get("conditions") or [])
        for sub in group.get("subgroups") or []:
            walk(sub)

    walk(rule.get("condition_group"))
    return out


def main():
    rules = mute_rules_by_number()
    if not rules:
        raise SystemExit("no rule is mute on the `nr` axis under the baseline — "
                         "either the baseline or the ruleset changed shape")

    lines = [
        "# wave7-nr-portions.txt — порции открытия оси `nr`, item б3 волны 7.",
        "# ГЕНЕРИРУЕТСЯ tools/rules-audit/nr-portions.py из rules/*.yaml.",
        "# Руками не правится: состав правил порции — следствие набора правил, а не решения.",
        "# Формат: <порция> <вид> <величина>. Вид: NR (номер), RULE (rule_id), PRICE (nr=вызовов/мин).",
        "#",
        "# Правило открывается ЛЮБЫМ своим номером, поэтому оно принадлежит ПЕРВОЙ",
        "# порции, содержащей хоть один из его номеров — той, чья цена его покупает.",
        "",
        "BASELINE NR " + ",".join(str(n) for n in BASELINE),
    ]
    for nr, why in sorted(EXCLUDED.items()):
        lines.append("EXCLUDED NR %d  # %s: %s" % (nr, NAMES.get(nr, "?"), why))
    lines.append("")

    taken = set()
    for pid, label, nrs in PORTIONS:
        opened = sorted(rid for rid, want in rules.items()
                        if rid not in taken and any(n in nrs for n in want))
        taken.update(opened)
        lines.append("# порция %s (%s): %d номеров, %d правил" % (pid, label, len(nrs), len(opened)))
        for nr in nrs:
            lines.append("P%s NR %d" % (pid, nr))
            lines.append("P%s PRICE %d=%d  # %s" % (pid, nr, PRICE[nr], NAMES.get(nr, "?")))
        for rid in opened:
            lines.append("P%s RULE %s" % (pid, rid))
        lines.append("")

    # Rules no portion buys. Their numbers were never measured by item б2, and a
    # number without a measured price is not opened — that is the whole rule of
    # this item. Recorded by name so the residue is a named class and not a gap.
    lines.append("# НЕ ПОКУПАЕТСЯ НИ ОДНОЙ ПОРЦИЕЙ (цена номеров не мерена item'ом б2):")
    left = sorted(set(rules) - taken)
    for rid in left:
        lines.append("UNBOUGHT RULE %s %s" % (rid, ",".join(str(n) for n in rules[rid])))
    lines.append("# итого: правил оси `nr` немых на baseline %d, покупается порциями %d, остаётся %d"
                 % (len(rules), len(taken), len(left)))

    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("написано: %s (немых %d, покупается %d в %d порциях, остаётся %d)"
          % (OUT, len(rules), len(taken), len(PORTIONS), len(left)))


if __name__ == "__main__":
    main()
