#!/usr/bin/env python3
"""Wave 8.2 stage 2 (B2/B3) — report for w82-pack.sh archives.

Usage: w82-pack-report.py <OUT dir fetched from the stand>

Per arm: max live entries of each sampled map against its declared size
(maps-pre.json), losses per collector over the attack window (every
events_dropped_total reason + bpf_map_full_total + the in-kernel unresolved
read/write counter — it is the fd_path miss counter, item 11), and the rule
firing set (alerts_total + dedup-dropped + rate-limited per rule, which is what
the rule layer produced before suppression). Then arm vs arm: rules present on
one side only and rules whose firing count moved by more than FACTOR.

Input to the verdict is computed here, not read off a table
(verdict-input-must-be-computed-by-emitter). A missing file is NEIZMERIM with
the class named, never a zero.
"""
import json
import os
import re
import sys
from collections import defaultdict

SER = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)')
LBL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
FACTOR = float(os.environ.get('FACTOR', '2.0'))
MIN_N = int(os.environ.get('MIN_N', '20'))  # below this a ratio is noise
SIZED = ['fd_path_map', 'syscall_args', 'conn_meta_map', 'conn_start_map', 'proc_args_map']


def load(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
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


def delta(pre, post):
    return {k: post[k] - pre.get(k, 0.0) for k in post}


def lab(key, name):
    return dict(key[1]).get(name, '')


def arm_report(d):
    r = {'dir': d}
    pre, post = load(f'{d}/m-pre.txt'), load(f'{d}/m-post.txt')
    r['metrics_ok'] = pre is not None and post is not None
    r['sha'] = open(f'{d}/bin.sha').read().strip() if os.path.exists(f'{d}/bin.sha') else '?'
    # fill
    sizes = {}
    if os.path.exists(f'{d}/maps-pre.json'):
        try:
            for m in json.load(open(f'{d}/maps-pre.json')):
                sizes[m.get('name', '')] = m.get('max_entries')
        except Exception:
            pass
    fill = defaultdict(int)
    n = 0
    if os.path.exists(f'{d}/fill.txt'):
        for line in open(f'{d}/fill.txt'):
            parts = line.split()
            if len(parts) < 2:
                continue
            n += 1
            for p in parts[1:]:
                k, _, v = p.partition('=')
                if v.isdigit():
                    fill[k] = max(fill[k], int(v))
    r['fill'] = {k: (fill.get(k), sizes.get(k)) for k in SIZED}
    r['fill_samples'] = n
    if not r['metrics_ok']:
        return r
    dl = delta(pre, post)
    drops = defaultdict(float)
    for k, v in dl.items():
        if k[0] == 'ebpf_guard_events_dropped_total' and v:
            drops[(lab(k, 'collector'), lab(k, 'reason'))] += v
    r['drops'] = dict(drops)
    r['map_full'] = {lab(k, 'map_name'): v for k, v in dl.items() if k[0] == 'ebpf_guard_bpf_map_full_total' and v}
    r['unresolved_rw'] = dl.get(('ebpf_guard_file_unresolved_rw_filtered_total', ()), None)
    r['events'] = sum(v for k, v in dl.items() if k[0] == 'ebpf_guard_events_total')
    fired = defaultdict(float)
    for k, v in dl.items():
        if k[0] in ('ebpf_guard_alerts_total', 'ebpf_guard_alerts_dedup_dropped_by_rule_total',
                    'ebpf_guard_alerts_ratelimited_by_rule_total') and v:
            fired[lab(k, 'rule_id')] += v
    r['fired'] = dict(fired)
    return r


def main():
    root = sys.argv[1]
    arms = sorted(x for x in os.listdir(root) if re.match(r'^\d+-\w+$', x))
    reps = [arm_report(f'{root}/{a}') for a in arms]
    for a, r in zip(arms, reps):
        print(f'== плечо {a} бинарь {r["sha"]}')
        if not r['metrics_ok']:
            print('   НЕИЗМЕРИМ: нет m-pre/m-post (класс: снимок метрик не снят)')
            continue
        print(f'   событий за окно {r["events"]:.0f}; сэмплов заполнения {r["fill_samples"]}')
        for k, (mx, sz) in r['fill'].items():
            pct = f'{100.0 * mx / sz:.1f}%' if mx is not None and sz else 'НЕИЗМЕРИМ'
            print(f'   заполнение {k:15s} макс {mx} из {sz}  ({pct})')
        print(f'   промахи fd_path (unresolved_rw): {r["unresolved_rw"]}')
        print(f'   map_full: {r["map_full"] or "0"}')
        for (c, why), v in sorted(r['drops'].items()):
            print(f'   потери {c}/{why}: {v:.0f}')
    if len(reps) >= 2 and all(r['metrics_ok'] for r in reps[:2]):
        a, b = reps[0]['fired'], reps[1]['fired']
        only_a = sorted(set(a) - set(b))
        only_b = sorted(set(b) - set(a))
        print(f'== тождество правил {arms[0]} vs {arms[1]}: A={len(a)} правил, B={len(b)}')
        print(f'   только в {arms[0]}: {only_a or "нет"}')
        print(f'   только в {arms[1]}: {only_b or "нет"}')
        moved = []
        for rid in sorted(set(a) & set(b)):
            x, y = a[rid], b[rid]
            if max(x, y) >= MIN_N and (y > x * FACTOR or x > y * FACTOR):
                moved.append((rid, x, y))
        print(f'   сдвиг более ×{FACTOR:g} при n>={MIN_N}: {moved or "нет"}')
        print('   (плечи на одном стенде в разное время: узел даёт свой фон — '
              'правила-таймеры ноды читаются по содержимому, не по счёту)')


if __name__ == '__main__':
    main()
