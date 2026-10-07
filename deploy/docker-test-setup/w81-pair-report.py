#!/usr/bin/env python3
"""Wave 8.1 items 7/11 — report for w81-pair-run.sh archives.

Usage: w81-pair-report.py <OUT dir fetched from the stand>

Per arm, over the idle window [m0, m1]: events/s, CPU us/event, file events by
op and path presence, in-kernel unresolved read/write filtered, losses (every
events_dropped_total reason except path_denylist), and alerts per rule on all
three layers (emitted, dedup-dropped, rate-limited) plus named exceptions.
item7 tail: the positive control's sentinels and the four log rules' alerts.
item11 tail: alerts per rule over the attack pack, arm A vs arm B.
Identity checks first: one sha for every arm, one agent copy, arm environment.
"""
import json
import os
import re
import sys

SER = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)')
LBL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def load(path):
    out = {}
    if not os.path.exists(path):
        return None
    for line in open(path, errors='replace'):
        if line.startswith('#'):
            continue
        m = SER.match(line)
        if not m:
            continue
        name, lbl, val = m.group(1), m.group(2) or '', m.group(3)
        try:
            v = float(val)
        except ValueError:
            continue
        out[(name, tuple(sorted(LBL.findall(lbl))))] = v
    return out


def delta(a, b, name, where=None):
    """Sum of b-a over series of `name` whose labels satisfy where(dict)."""
    tot = 0.0
    for (n, l), v in b.items():
        if n != name:
            continue
        d = dict(l)
        if where and not where(d):
            continue
        tot += v - a.get((n, l), 0.0)
    return tot


def by_label(a, b, name, key):
    res = {}
    for (n, l), v in b.items():
        if n != name:
            continue
        d = dict(l)
        k = key(d)
        res[k] = res.get(k, 0.0) + v - a.get((n, l), 0.0)
    return {k: v for k, v in res.items() if v}


def read(p, default=''):
    try:
        return open(p).read().strip()
    except OSError:
        return default


LOG_RULES = ['evasion_log_clear', 'defense_evasion_journald_log_clear',
             'ransomware_log_wipe', 'impact_mass_file_deletion_critical']


def three_layers(a, b):
    em = by_label(a, b, 'ebpf_guard_alerts_total', lambda d: d.get('rule_id'))
    dd = by_label(a, b, 'ebpf_guard_alerts_dedup_dropped_by_rule_total', lambda d: d.get('rule_id'))
    rl = by_label(a, b, 'ebpf_guard_alerts_ratelimited_by_rule_total', lambda d: d.get('rule_id'))
    ex = by_label(a, b, 'ebpf_guard_rule_exceptions_total', lambda d: (d.get('rule_id'), d.get('exception_name')))
    rules = set(em) | set(dd) | set(rl)
    return {r: (em.get(r, 0), dd.get(r, 0), rl.get(r, 0)) for r in rules}, ex


def main():
    out = sys.argv[1]
    arms = sorted(d for d in os.listdir(out) if re.match(r'\d+-[AB]$', d))
    print(f'archive {out}: bin sha {read(os.path.join(out, "bin.sha"))}, arms {arms}')
    if os.path.exists(os.path.join(out, 'DIE')):
        print('DIE:', read(os.path.join(out, 'DIE')))
    shas = {read(os.path.join(out, d, 'sha')) for d in arms}
    print(f'identity: process sha {sorted(shas)} ({"ONE" if len(shas) == 1 else "DIFFERENT — pair invalid"})')
    per_arm = {}
    for d in arms:
        D = os.path.join(out, d)
        m0, m1 = load(os.path.join(D, 'm0.txt')), load(os.path.join(D, 'm1.txt'))
        if m0 is None or m1 is None:
            print(f'{d}: window snapshots missing')
            continue
        dt = float(read(os.path.join(D, 't1'), '0')) - float(read(os.path.join(D, 't0'), '0'))
        ev = delta(m0, m1, 'ebpf_guard_events_total')
        fev = delta(m0, m1, 'ebpf_guard_events_total', lambda l: l.get('type') == 'file')
        cpu = delta(m0, m1, 'process_cpu_seconds_total')
        ops = by_label(m0, m1, 'ebpf_guard_file_events_by_op_total', lambda l: f"{l['op']}/{l['path']}")
        unres = delta(m0, m1, 'ebpf_guard_file_unresolved_rw_filtered_total')
        loss = by_label(m0, m1, 'ebpf_guard_events_dropped_total',
                        lambda l: f"{l.get('collector', l.get('source', '?'))}/{l.get('reason')}")
        loss = {k: v for k, v in loss.items() if not k.endswith('/path_denylist')}
        layers, ex = three_layers(m0, m1)
        print(f'\n== {d}  env={read(os.path.join(D, "env")).replace(chr(10), " ") or "-"}  copies={read(os.path.join(D, "ncopies"))}  window {dt:.0f}s')
        print(f'   events {ev / dt:.0f}/s (file {fev / dt:.0f}/s), CPU {1e6 * cpu / ev if ev else 0:.1f} us/event, '
              f'{100 * cpu / dt:.1f}% core, memory.current {int(read(os.path.join(D, "memcur"), "0")) / 2**20:.1f} MiB')
        print('   file events by op/path per min:', {k: round(v * 60 / dt, 1) for k, v in sorted(ops.items())})
        print(f'   unresolved rw filtered in kernel: {unres * 60 / dt:.0f}/min')
        print('   losses (excl. path_denylist):', loss or 0)
        tot = [sum(x[i] for x in layers.values()) for i in range(3)]
        print(f'   alerts emitted/dedup/ratelimited: {tot[0]:.0f}/{tot[1]:.0f}/{tot[2]:.0f}')
        for r in LOG_RULES + ['evasion_system_binary_replace', 'defense_evasion_binary_truncate_pad', 'anomaly_detection']:
            if r in layers:
                print(f'     {r}: {layers[r]}')
        lex = {k: v for k, v in ex.items() if k[0] in LOG_RULES}
        if lex:
            print('   log-rule exceptions:', lex)
        per_arm[d] = dict(cpu_ev=1e6 * cpu / ev if ev else 0, layers=layers)
        if os.path.exists(os.path.join(D, 'control.txt')):
            print('   control sentinels:', read(os.path.join(D, 'control.txt')).replace('\n', ' | '))
            mc = load(os.path.join(D, 'm-ctl.txt'))
            if mc:
                cl, _ = three_layers(m1, mc)
                print('   control alerts (3 layers):', {r: cl.get(r, (0, 0, 0)) for r in LOG_RULES})
            try:
                js = json.load(open(os.path.join(D, 'alerts-ctl.json')))
                items = js if isinstance(js, list) else js.get('alerts', js.get('items', []))
                names = sorted({a.get('rule_id') for a in items if a.get('rule_id') in LOG_RULES})
                print('   control alerts in store:', names)
            except (OSError, ValueError, AttributeError) as e:
                print('   control alerts in store: unreadable', e)
        a0, a1 = load(os.path.join(D, 'm-att0.txt')), load(os.path.join(D, 'm-att1.txt'))
        if a0 and a1:
            al, _ = three_layers(a0, a1)
            per_arm[d]['attack'] = al
            print(f'   attack pack: rc={read(os.path.join(D, "attacks.rc"))}, rules with alerts {len(al)}, '
                  f'emitted {sum(x[0] for x in al.values()):.0f}')
    att = {d: v['attack'] for d, v in per_arm.items() if 'attack' in v}
    if att:
        print('\n== attack pack, rules present by arm (any layer):')
        allr = sorted(set().union(*[set(v) for v in att.values()]))
        for r in allr:
            row = {d: int(sum(att[d].get(r, (0, 0, 0)))) for d in sorted(att)}
            if len(set(1 if x else 0 for x in row.values())) > 1:
                print(f'   DIFF {r}: {row}')
        print(f'   rules compared: {len(allr)} (only presence differences printed)')


if __name__ == '__main__':
    main()
