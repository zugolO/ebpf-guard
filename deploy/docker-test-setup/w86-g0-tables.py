#!/usr/bin/env python3
"""Волна 8.6, G0: таблицы из вывода TestG0MixProfile (internal/correlator/g0_mix_test.go).

  w86-g0-tables.py OUT_DIR [NIGHT_PPROF_GLOB]

OUT_DIR — каталог G0_OUT (cpu-plain.pprof, cpu-labels.pprof, regex-probe.tsv).
NIGHT_PPROF_GLOB — профили ночи для сравнения долей (по умолчанию ночь 8.5).
Печатает: доли узлов в EvaluateInto бенча против ночи, CPU по event_type и
rule_file, топ-20 правил по CPU с колонкой «литерал прошёл, regex не совпал».
Доли узлов — от EvaluateInto (бенч не содержит остального агента).
"""
import csv, glob, re, subprocess, sys

out = sys.argv[1]
night = sys.argv[2] if len(sys.argv) > 2 else \
    "server-logs/collect-8.5-night/night-8.5-night/idle/snapshots/cpu-00*.pprof"

def pprof(*args):
    return subprocess.run(["go", "tool", "pprof", *args], capture_output=True, text=True).stdout

def secs(tok):
    m = re.match(r"([\d.]+)(ms|s|us)$", tok)
    v = float(m.group(1))
    return v / 1000 if m.group(2) == "ms" else v / 1e6 if m.group(2) == "us" else v

def nodes(files):
    txt = pprof("-top", "-cum", "-nodecount=400", *files)
    res = {}
    for l in txt.splitlines():
        p = l.split()
        if len(p) >= 6 and p[0][0].isdigit():
            res[p[5]] = secs(p[3])
    return res

KEYS = ["RuleEngine).EvaluateInto", "RuleEngine).matchesRegex", "correlator.containsAny",
        "regexp.(*Regexp).tryBacktrack", "RuleEngine).evaluateConditionGroup",
        "RuleEngine).getFieldValueCached"]

def pick(res, key):
    for k, v in res.items():
        if key in k:
            return v
    return float("nan")

n = nodes(sorted(glob.glob(night)))
b = nodes([out + "/cpu-plain.pprof"])
print("## доли узлов в EvaluateInto: ночь 8.5 против бенча")
print("| узел | ночь, с | доля EvaluateInto | бенч, с | доля EvaluateInto | Δ, п. |")
print("|---|---|---|---|---|---|")
ne, be = pick(n, KEYS[0]), pick(b, KEYS[0])
for k in KEYS:
    nv, bv = pick(n, k), pick(b, k)
    print(f"| {k} | {nv:.2f} | {100*nv/ne:.1f}% | {bv:.2f} | {100*bv/be:.1f}% | {100*bv/be-100*nv/ne:+.1f} |")

lab = pprof("-tags", out + "/cpu-labels.pprof")
sect = {}
cur = None
for l in lab.splitlines():
    m = re.match(r"^ (\w+): Total", l)
    if m:
        cur = m.group(1); sect[cur] = []; continue
    m = re.match(r"^\s+([\d.]+(?:ms|s|us)) \(\s*([\d.]+)%\): (.+)$", l)
    if m and cur:
        sect[cur].append((m.group(3), secs(m.group(1)), float(m.group(2))))
print("\n## CPU по event_type (метка pprof)")
print("| event_type | с | доля |\n|---|---|---|")
for k, v, p in sect.get("event_type", []):
    print(f"| {k} | {v:.2f} | {p:.1f}% |")
print("\n## CPU по файлу правил (топ-10)")
print("| rule_file | с | доля |\n|---|---|---|")
for k, v, p in sect.get("rule_file", [])[:10]:
    print(f"| {k} | {v:.2f} | {p:.1f}% |")

probe = {}
with open(out + "/regex-probe.tsv") as f:
    for r in csv.DictReader(f, delimiter="\t"):
        probe[r["rule_id"]] = r
print("\n## топ-20 правил по CPU")
print("| # | rule_id | с | доля | вызовов шаблонов | литерал прошёл | regex совпал | впустую |")
print("|---|---|---|---|---|---|---|---|")
for i, (k, v, p) in enumerate(sect.get("rule_id", [])[:20], 1):
    r = probe.get(k, {})
    print(f"| {i} | {k} | {v:.2f} | {p:.1f}% | {r.get('pattern_calls','-')} | {r.get('literal_passed','-')} | {r.get('regex_matched','-')} | {r.get('wasted_regex','-')} |")
tot20 = sum(p for _, _, p in sect.get("rule_id", [])[:20])
print(f"\nтоп-20 правил = {tot20:.1f}% CPU; топ-3 = {sum(p for _,_,p in sect.get('rule_id', [])[:3]):.1f}%")
