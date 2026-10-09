#!/usr/bin/env python3
"""№549 — цена одного события ноды по таймеру из архива w549-node-price.sh.

Usage: w549-node-price-report.py <OUT dir fetched from the stand>

Per target: three layers per rule (emitted / dedup / rate-limited) as the
delta of window E minus the delta of control window C of the same length;
emitted alerts of window E grouped by tree root (process_tree[0]) — the price
of the event is the target's own tree; incidents opened inside E by verdict.
Prints numbers only: this is a measurement, no thresholds are set (№549 —
the owner decides).
"""
import datetime
import json
import os
import re
import sys

SER = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)')
LBL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
LAYERS = (('emitted', 'ebpf_guard_alerts_total'),
          ('dedup', 'ebpf_guard_alerts_dedup_dropped_by_rule_total'),
          ('limiter', 'ebpf_guard_alerts_ratelimited_by_rule_total'))
# Корни дерева события по цели (comm обрезан ядром до 15 байт).
ROOTS = {
    'apt-daily.service': {'apt.systemd.dai', 'apt-helper'},
    'apt-daily-upgrade.service': {'apt.systemd.dai', 'apt-helper', 'unattended-upgr'},
    'fwupd-refresh.service': {'fwupdmgr', 'fwupd'},
}


def load(path):
    out = {}
    for line in open(path, errors='replace'):
        if line.startswith('#'):
            continue
        m = SER.match(line)
        if not m:
            continue
        try:
            v = float(m.group(3))
        except ValueError:
            continue
        out[(m.group(1), tuple(sorted(LBL.findall(m.group(2) or ''))))] = v
    return out


def per_rule(a, b, name):
    out = {}
    for (n, l), v in b.items():
        if n != name:
            continue
        rid = dict(l).get('rule_id')
        if rid is None:
            continue
        d = v - a.get((n, l), 0.0)
        if d:
            out[rid] = out.get(rid, 0.0) + d
    return out


def total(a, b, name, **want):
    t = 0.0
    for (n, l), v in b.items():
        if n == name and all(dict(l).get(k) == x for k, x in want.items()):
            t += v - a.get((n, l), 0.0)
    return int(t)


def alerts(path):
    try:
        data = json.load(open(path))
    except (OSError, ValueError):
        return []
    if isinstance(data, dict):
        data = data.get('alerts') or data.get('items') or data.get('incidents') or []
    return data


def ts(s):
    s = s.rstrip('Z')
    if '.' in s:
        head, frac = s.split('.', 1)
        s = head + '.' + frac[:6]
    return datetime.datetime.fromisoformat(s).replace(tzinfo=datetime.timezone.utc).timestamp()


def target(d):
    u = open(os.path.join(d, 'target')).read().strip()
    w = int(open(os.path.join(d, 'window')).read())
    print(f'\n=== {u} (окно {w} с) ===')
    if os.path.exists(os.path.join(d, 'skipped')):
        print('  ПРОПУЩЕН:', open(os.path.join(d, 'skipped')).read().strip())
        return None
    print('  ' + open(os.path.join(d, 'unit.txt')).read().strip().replace('\n', '\n  '))
    c0, c1, e0, e1 = (load(os.path.join(d, f)) for f in ('mC0.txt', 'mC1.txt', 'mE0.txt', 'mE1.txt'))
    tE0 = int(open(os.path.join(d, 'tE0')).read())
    tE1 = int(open(os.path.join(d, 'tE1')).read())

    rows = {}
    for layer, name in LAYERS:
        c = per_rule(c0, c1, name)
        e = per_rule(e0, e1, name)
        for rid in set(c) | set(e):
            rows.setdefault(rid, {})[layer] = int(e.get(rid, 0) - c.get(rid, 0))
    price = {rid: sum(v.values()) for rid, v in rows.items()}
    tot = {layer: sum(v.get(layer, 0) for v in rows.values()) for layer, _ in LAYERS}
    print(f'  E − C по трём слоям: выпущено {tot["emitted"]} / дедуп {tot["dedup"]} / лимитер {tot["limiter"]}')
    print('  правила (E − C, сумма слоёв ≠ 0, по убыванию):')
    for rid in sorted(price, key=lambda r: -price[r])[:25]:
        if price[rid] == 0:
            continue
        v = rows[rid]
        print(f'    {price[rid]:+7d}  {v.get("emitted", 0):+6d}/{v.get("dedup", 0):+6d}/{v.get("limiter", 0):+6d}  {rid}')
    for verdict in ('attack', 'suspicious', 'benign'):
        c = total(c0, c1, 'ebpf_guard_incidents_total', verdict=verdict)
        e = total(e0, e1, 'ebpf_guard_incidents_total', verdict=verdict)
        print(f'  инцидентов {verdict}: окно E {e}, окно C {c}')

    al = [a for a in alerts(os.path.join(d, 'alerts-E.json')) if tE0 <= ts(a['timestamp']) <= tE1 + 1]
    roots = {}
    for a in al:
        pt = a.get('process_tree') or []
        r = (pt[0].get('comm'), pt[0].get('pid')) if pt else ('(нет дерева)', 0)
        roots.setdefault(r, []).append(a)
    print(f'  выпущено в сторе за E: {len(al)}; по корням дерева:')
    for (comm, pid), lst in sorted(roots.items(), key=lambda kv: -len(kv[1]))[:12]:
        print(f'    {len(lst):5d}  {comm} (pid {pid})')
    own = [a for (comm, _), lst in roots.items() if comm in ROOTS.get(u, set()) for a in lst]
    by_rule = {}
    for a in own:
        by_rule[a['rule_id']] = by_rule.get(a['rule_id'], 0) + 1
    print(f'  ЦЕНА СОБЫТИЯ (выпущено, корни {sorted(ROOTS.get(u, set()))}): {len(own)}')
    for rid, k in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print(f'    {k:5d}  {rid}')
    inc = [i for i in alerts(os.path.join(d, 'incidents.json'))
           if tE0 <= ts(i.get('first_seen') or '1970-01-01T00:00:00Z') <= tE1 + 1]
    for i in inc:
        print(f'  инцидент {i.get("id")} {i.get("first_seen", "")[11:19]} verdict={i.get("verdict")} '
              f'score={round(i.get("score") or 0, 1)} корень={i.get("root_comm")} '
              f'rules={sorted(set(i.get("rule_ids") or []))[:10]}')
    return len(own), tot


def main():
    d = sys.argv[1]
    ident = dict(l.strip().split('=', 1) for l in open(os.path.join(d, 'binary-identity.txt')) if '=' in l)
    print(f"бинарь: файл {ident.get('sha256', '?')[:12]} процесс {ident.get('sha256_proc', '?')[:12]}")
    for sub in sorted(x for x in os.listdir(d) if os.path.isdir(os.path.join(d, x))):
        target(os.path.join(d, sub))


if __name__ == '__main__':
    main()
